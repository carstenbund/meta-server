from flask import Flask, request, jsonify
import fitz  # PyMuPDF
import docx
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification, pipeline
from transformers import BartTokenizer, BartForConditionalGeneration
import spacy
import os

app = Flask(__name__)

# Set the custom cache directory (optional)
os.environ['TRANSFORMERS_CACHE'] = '/path/to/custom/cache'

# Initialize the DistilBERT tokenizer and model for category inference
tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
model = DistilBertForSequenceClassification.from_pretrained('distilbert-base-uncased')
classifier = pipeline('sentiment-analysis', model=model, tokenizer=tokenizer)

# Initialize the BART tokenizer and model for summarization
summarizer_tokenizer = BartTokenizer.from_pretrained('facebook/bart-large-cnn')
summarizer_model = BartForConditionalGeneration.from_pretrained('facebook/bart-large-cnn')
summarizer = pipeline('summarization', model=summarizer_model, tokenizer=summarizer_tokenizer)

# Initialize spaCy for keyword extraction
nlp = spacy.load("en_core_web_sm")

# Set the base directory for file storage
BASE_DIR = '/path/to/your/files'

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

def infer_category(text):
    results = classifier(text)
    return results[0]['label'] if results else 'N/A'

def extract_keywords(text):
    doc = nlp(text)
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

    return jsonify({
        'inferred_category': infer_category(content),
        'keywords': extract_keywords(content),
        'summary': summarize_content(content)
    })

if __name__ == '__main__':

    WEB_IP = '0.0.0.0'
    WEB_PORT = 5001

    app.run(port=WEB_PORT, host=WEB_IP, debug=True, use_reloader=False)

