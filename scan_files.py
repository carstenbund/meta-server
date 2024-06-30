import os
import fitz  # PyMuPDF
import docx
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
from transformers import MarianMTModel, MarianTokenizer, BartTokenizer, BartForConditionalGeneration
from langdetect import detect
import spacy
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database setup
DATABASE_URI = 'sqlite:///files.db'
Base = declarative_base()
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
session = Session()

# Define the FileMetadata model
class FileMetadata(Base):
    __tablename__ = 'file_metadata'
    id = Column(Integer, primary_key=True, autoincrement=True)
    path = Column(String, unique=True, nullable=False)
    size = Column(Integer, nullable=False)
    modification_date = Column(Float, nullable=False)
    category = Column(String, nullable=True)
    keywords = Column(String, nullable=True)
    summary = Column(String, nullable=True)
    content = Column(String, nullable=False)

# Ensure database tables are created
Base.metadata.create_all(engine)

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

def extract_text_from_txt(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

def translate_text(text, source_lang, target_lang='en'):
    if source_lang == 'nl' and target_lang == 'en':
        return nl_to_en_translator(text, max_length=512)[0]['translation_text']
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

def scan_directory(directory):
    for subdir, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(subdir, file)
            file_extension = os.path.splitext(file_path)[1].lower()
            
            if file_extension in ['.pdf', '.docx', '.txt']:
                if file_extension == '.pdf':
                    content = extract_text_from_pdf(file_path)
                elif file_extension == '.docx':
                    content = extract_text_from_docx(file_path)
                elif file_extension == '.txt':
                    content = extract_text_from_txt(file_path)
                
                # Detect the language of the content
                source_lang = detect(content)
                if source_lang == 'nl':
                    content = translate_text(content, source_lang, 'en')

                inferred_category = infer_category(content, 'en')
                keywords = extract_keywords(content, 'en')
                summary = summarize_content(content)

                metadata = FileMetadata(
                    path=file_path,
                    size=os.path.getsize(file_path),
                    modification_date=os.path.getmtime(file_path),
                    category=inferred_category,
                    keywords=keywords,
                    summary=summary,
                    content=content
                )
                session.add(metadata)
                session.commit()

if __name__ == '__main__':
    directory_to_scan = '/path/to/your/files'
    scan_directory(directory_to_scan)

