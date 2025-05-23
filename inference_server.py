from flask import Flask, request, jsonify
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification, MarianTokenizer, MarianMTModel, BartTokenizer, BartForConditionalGeneration
import spacy

app = Flask(__name__)

# Initialize models and pipelines
english_tokenizer = AutoTokenizer.from_pretrained('distilbert-base-uncased')
english_model = AutoModelForSequenceClassification.from_pretrained('distilbert-base-uncased')
english_classifier = pipeline('text-classification', model=english_model, tokenizer=english_tokenizer)

dutch_tokenizer = AutoTokenizer.from_pretrained('wietsedv/bert-base-dutch-cased')
dutch_model = AutoModelForSequenceClassification.from_pretrained('wietsedv/bert-base-dutch-cased')
dutch_classifier = pipeline('text-classification', model=dutch_model, tokenizer=dutch_tokenizer)

summarizer_tokenizer = BartTokenizer.from_pretrained('facebook/bart-large-cnn')
summarizer_model = BartForConditionalGeneration.from_pretrained('facebook/bart-large-cnn')
summarizer = pipeline('summarization', model=summarizer_model, tokenizer=summarizer_tokenizer)

spacy_en = spacy.load("en_core_web_sm")
spacy_nl = spacy.load("nl_core_news_sm")

nl_to_en_tokenizer = MarianTokenizer.from_pretrained('Helsinki-NLP/opus-mt-nl-en')
nl_to_en_model = MarianMTModel.from_pretrained('Helsinki-NLP/opus-mt-nl-en')
nl_to_en_translator = pipeline('translation', model=nl_to_en_model, tokenizer=nl_to_en_tokenizer)

def translate_text(text, source_lang, target_lang='en'):
    if source_lang == 'nl' and target_lang == 'en':
        return nl_to_en_translator(text, max_length=512)[0]['translation_text']
    return text

def infer_category(text, language='en'):
    max_length = 512
    truncated_text = text[:max_length]

    if language == 'nl':
        results = dutch_classifier(truncated_text)
    else:
        results = english_classifier(truncated_text)
    return results[0]['label'] if results else 'N/A'

def extract_keywords(text, language='en'):
    if language == 'nl':
        doc = spacy_nl(text)
    else:
        doc = spacy_en(text)
    keywords = [chunk.text for chunk in doc.noun_chunks]
    return ', '.join(keywords)

def summarize_content(text):
    max_length = 1024
    chunks = [text[i:i + max_length] for i in range(0, len(text), max_length)]
    summaries = [summarizer(chunk, max_length=150, min_length=40, do_sample=False)[0]['summary_text'] for chunk in chunks]
    return ' '.join(summaries)

@app.route('/infer', methods=['POST'])
def infer():
    data = request.json
    content = data.get('content')
    print("processing ", content)
    source_lang = data.get('language')

    if source_lang == 'nl':
        content = translate_text(content, source_lang, 'en')
        print("translate nl en")

    category = infer_category(content, 'en')
    keywords = extract_keywords(content, 'en')
    summary = summarize_content(content)

    return jsonify({
        'category': category,
        'inferred_category': category,
        'keywords': keywords,
        'summary': summary
    })

if __name__ == '__main__':
    app.run(port=5001, debug=True, use_reloader=False)


