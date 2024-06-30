from flask import Flask, request, jsonify
import fitz  # PyMuPDF
import docx
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
from transformers import MarianMTModel, MarianTokenizer, BartTokenizer, BartForConditionalGeneration
from langdetect import detect
import spacy
import os

app = Flask(__name__)

# Set the custom cache directory (optional)
os.environ['TRANSFORMERS_CACHE'] = '/var/server/data/transformers/cache'

# Initialize the tokenizer and model for English text classification
english_tokenizer = AutoTokenizer.from_pretrained('distilbert-base-uncased')
english_model = AutoModelForSequenceClassification.from_pretrained('distilbert-base-uncased')
english_classifier = pipeline('text-classification', model=english_model, tokenizer=english_tokenizer)

# Initialize the tokenizer and model for Dutch text classification
dutch_tokenizer = AutoTokenizer.from_pretrained('wietsedv/bert-base-dutch-cased')
dutch_model = AutoModelForSequenceClassification.from_pretrained('wietsedv/bert-base-dutch-cased')
dutch_classifier = pipeline('text-classification', model=dutch_model, tokenizer=dutch_tokenizer)

# Initialize the tokenizer and model for English summarization
summarizer_tokenizer = BartTokenizer.from_pretrained('facebook/bart-large-cnn')
summarizer_model = BartForConditionalGeneration.from_pretrained('facebook/bart-large-cnn')
summarizer = pipeline('summarization', model=summarizer_model, tokenizer=summarizer_tokenizer)

# Initialize spaCy for keyword extraction in English and Dutch
spacy_en = spacy.load("en_core_web_sm")
spacy_nl = spacy.load("nl_core_news_sm")

# Initialize translation models
nl_to_en_tokenizer = MarianTokenizer.from_pretrained('Helsinki-NLP/opus-mt-nl-en')
nl_to_en_model = MarianMTModel.from_pretrained('Helsinki-NLP/opus-mt-nl-en')
nl_to_en_translator = pipeline('translation', model=nl_to_en_model, tokenizer=nl_to_en_tokenizer)

en_to_ja_tokenizer = MarianTokenizer.from_pretrained('Helsinki-NLP/opus-mt-en-jap')
en_to_ja_model = MarianMTModel.from_pretrained('Helsinki-NLP/opus-mt-en-jap')
en_to_ja_translator = pipeline('translation', model=en_to_ja_model, tokenizer=en_to_ja_tokenizer)

# Set the base directory for file storage
BASE_DIR = '/win95/mcrlnsalg/'

def extract_text_from_pdf(file_path):
    doc = fitz.open(file_path)
    text = ""
    for page in doc:
        text += page.get_text()
    return text

def extract_text_from_docx(file_path):
    doc = docx.Document(file_path)
    text = []
    for paragraph in doc.paragraphs:
        text.append(paragraph.text)
    return '\n'.join(text)

def translate_text(text, source_lang, target_lang='en'):
    if source_lang == 'nl' and target_lang == 'en':
        return nl_to_en_translator(text, max_length=512)[0]['translation_text']
    elif source_lang == 'en' and target_lang == 'ja':
        return en_to_ja_translator(text, max_length=512)[0]['translation_text']
    return text  # No translation needed if already in target language

def infer_category(text, language='en'):
    if language == 'nl':
        results = dutch_classifier(text)
    else:
        results = english_classifier(text)
    return results[0]['label'] if results else 'N/A'

def extract_keywords(text, language='en'):
    if language == 'nl':
        doc = spacy_nl(text)
    else:
        doc = spacy_en(text)
    keywords = [chunk.text for chunk in doc.noun_chunks]
    return ', '.join(keywords)

def summarize_content(text):
    results = summarizer(text, max_length=150, min_length=40, do_sample=False)
    return results[0]['summary_text'] if results else 'N/A'

@app.route('/infer', methods=['POST'])
def infer():
    relative_path = request.json.get('file_path')
    if not relative_path:
        return jsonify({'error': 'No file path provided'}), 400

    file_path = os.path.join(BASE_DIR, relative_path)
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404

    content = ""
    if file_path.lower().endswith('.pdf'):
        content = extract_text_from_pdf(file_path)
    elif file_path.lower().endswith('.docx'):
        content = extract_text_from_docx(file_path)
    else:
        return jsonify({'error': 'Unsupported file type'}), 400

    # Detect the language of the content
    source_lang = detect(content)
    if source_lang == 'nl':
        content = translate_text(content, source_lang, 'en')

    inferred_category = infer_category(content, 'en')
    keywords = extract_keywords(content, 'en')
    summary = summarize_content(content)

    return jsonify({
        'inferred_category': inferred_category,
        'keywords': keywords,
        'summary': summary,
        'content': content  # Include the English content
    })

@app.route('/translate', methods=['POST'])
def translate():
    text = request.json.get('text')
    target_lang = request.json.get('target_lang')
    if not text or not target_lang:
        return jsonify({'error': 'Text and target language must be provided'}), 400

    source_lang = detect(text)
    translated_text = translate_text(text, source_lang, target_lang)
    
    return jsonify({'translated_text': translated_text})

if __name__ == '__main__':
    app.run(port=5001, debug=True)

