#!/usr/bin/env python3
"""
Enhanced Document Preprocessing Module

Provides comprehensive text cleaning and preprocessing for document content
before sending to LLMs. Removes artifacts, formats, and noise to focus on
substantive subject matter for better categorization, keyword extraction,
and summarization.

Key features:
- Removes headers, footers, page numbers, and metadata artifacts
- Cleans Tika extraction artifacts and formatting noise
- Handles tables and special formatting
- Smart chunking strategies for long documents
- Language-aware text processing
"""

import re
from typing import List, Optional, Tuple
import logging

log = logging.getLogger(__name__)


class DocumentPreprocessor:
    """Enhanced document preprocessor for cleaning raw text before LLM processing"""

    # Common document artifacts patterns
    HEADER_FOOTER_PATTERNS = [
        # Page numbers (various formats)
        r'^\s*-?\s*\d+\s*-?\s*$',  # "- 5 -" or "5" on its own line
        r'^\s*Page\s+\d+\s*(?:of\s+\d+)?\s*$',  # "Page 5" or "Page 5 of 10"
        r'^\s*\d+\s*/\s*\d+\s*$',  # "5 / 10"
        r'^\s*\[\s*\d+\s*\]\s*$',  # "[5]"

        # Common header/footer text
        r'^\s*(?:CONFIDENTIAL|DRAFT|INTERNAL|PROPRIETARY)\s*$',
        r'^\s*©.*?\d{4}.*$',  # Copyright notices
        r'^\s*Copyright\s+©?\s*\d{4}',
        r'^\s*All\s+[Rr]ights\s+[Rr]eserved\s*$',

        # Document metadata
        r'^\s*(?:Document|File)\s*(?:ID|Number|Ref)?\s*:?\s*[\w-]+\s*$',
        r'^\s*Version\s*:?\s*[\d.]+\s*$',
        r'^\s*Rev(?:ision)?\s*:?\s*[\d.]+\s*$',
        r'^\s*Date\s*:?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\s*$',
    ]

    # Tika extraction artifacts
    TIKA_ARTIFACTS = [
        r'\x0c',  # Form feed characters
        r'\ufffd',  # Unicode replacement character
        r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]',  # Control characters except \t, \n, \r
    ]

    # Repeated separators and decorative elements
    SEPARATOR_PATTERNS = [
        r'^[=_\-*#]{3,}\s*$',  # Lines of repeated characters (===, ___, ---, etc.)
        r'^\.{3,}\s*$',  # Dot leaders (...)
        r'^\s*[•·∙○●◦‣⁃]\s*$',  # Bullet points on their own line
    ]

    # Table artifacts and formatting
    TABLE_ARTIFACTS = [
        r'\|{2,}',  # Multiple pipe characters
        r'_{3,}',  # Underscores used as table lines (but not in text)
    ]

    def __init__(self):
        """Initialize the preprocessor with compiled regex patterns"""
        self.header_footer_compiled = [re.compile(p, re.IGNORECASE) for p in self.HEADER_FOOTER_PATTERNS]
        self.separator_compiled = [re.compile(p) for p in self.SEPARATOR_PATTERNS]

    def clean_tika_artifacts(self, text: str) -> str:
        """
        Remove Tika extraction artifacts and control characters

        Args:
            text: Raw text from Tika

        Returns:
            Text with artifacts removed
        """
        for pattern in self.TIKA_ARTIFACTS:
            text = re.sub(pattern, '', text)
        return text

    def remove_headers_footers(self, text: str) -> str:
        """
        Remove common header/footer patterns and page numbers

        Args:
            text: Input text

        Returns:
            Text with headers/footers removed
        """
        lines = text.split('\n')
        cleaned_lines = []

        for line in lines:
            # Check against all header/footer patterns
            is_artifact = False
            for pattern in self.header_footer_compiled:
                if pattern.match(line.strip()):
                    is_artifact = True
                    break

            # Check against separator patterns
            if not is_artifact:
                for pattern in self.separator_compiled:
                    if pattern.match(line.strip()):
                        is_artifact = True
                        break

            # Keep line if it's not an artifact
            if not is_artifact:
                cleaned_lines.append(line)

        return '\n'.join(cleaned_lines)

    def normalize_whitespace(self, text: str, preserve_paragraphs: bool = True) -> str:
        """
        Normalize whitespace while preserving document structure

        Args:
            text: Input text
            preserve_paragraphs: If True, preserve paragraph breaks (double newlines)

        Returns:
            Text with normalized whitespace
        """
        # Remove tabs and replace with spaces
        text = text.replace('\t', ' ')

        # Collapse multiple spaces to single space
        text = re.sub(r' {2,}', ' ', text)

        if preserve_paragraphs:
            # Preserve paragraph breaks (2+ newlines become 2 newlines)
            text = re.sub(r'\n\s*\n+', '\n\n', text)
            # Remove spaces at line ends
            text = re.sub(r' +\n', '\n', text)
        else:
            # Collapse all newlines to single newline
            text = re.sub(r'\n+', '\n', text)

        return text.strip()

    def clean_table_artifacts(self, text: str) -> str:
        """
        Clean up table formatting artifacts

        Tables in extracted text often have poor formatting. This cleans up
        common table artifacts while preserving readable content.

        Args:
            text: Input text

        Returns:
            Text with table artifacts cleaned
        """
        # Remove excessive pipe characters (often used in table borders)
        text = re.sub(r'\|{2,}', '|', text)

        # Remove table separator lines (multiple dashes/underscores)
        # But keep reasonable dashes in text (like bullet points)
        lines = text.split('\n')
        cleaned_lines = []

        for line in lines:
            # If line is mostly dashes/underscores/pipes, skip it
            non_table_chars = re.sub(r'[\s\-_|+=]', '', line)
            if len(non_table_chars) > 3 or len(line.strip()) == 0:
                # Line has substantial content or is blank
                cleaned_lines.append(line)
            # else: skip lines that are mostly table formatting

        return '\n'.join(cleaned_lines)

    def remove_repeated_content(self, text: str, min_length: int = 20) -> str:
        """
        Remove repeated sentences/lines that often appear in headers/footers

        Args:
            text: Input text
            min_length: Minimum length of text chunks to check for repetition

        Returns:
            Text with repeated content removed
        """
        lines = text.split('\n')

        # Track seen lines with substantial content
        seen_lines = set()
        unique_lines = []

        for line in lines:
            stripped = line.strip()

            # Keep short lines and empty lines (they're usually not repetitive headers)
            if len(stripped) < min_length:
                unique_lines.append(line)
                continue

            # Check if we've seen this exact line before
            if stripped.lower() not in seen_lines:
                seen_lines.add(stripped.lower())
                unique_lines.append(line)
            # else: skip repeated line

        return '\n'.join(unique_lines)

    def extract_main_content(self, text: str, min_line_length: int = 10) -> str:
        """
        Extract main content by filtering out very short lines that are often metadata

        Args:
            text: Input text
            min_line_length: Minimum length for a line to be considered content

        Returns:
            Main content text
        """
        lines = text.split('\n')
        content_lines = []

        for line in lines:
            stripped = line.strip()

            # Keep empty lines (paragraph breaks)
            if len(stripped) == 0:
                content_lines.append(line)
                continue

            # Keep lines that meet minimum length
            # This filters out isolated words, labels, etc.
            if len(stripped) >= min_line_length:
                content_lines.append(line)

        return '\n'.join(content_lines)

    def clean_document_metadata(self, text: str) -> str:
        """
        Remove common document metadata sections

        Args:
            text: Input text

        Returns:
            Text with metadata removed
        """
        # Remove common metadata prefixes at line starts
        metadata_patterns = [
            r'^(?:Author|Title|Subject|Keywords|Creator|Producer|Created|Modified)\s*:.*$',
            r'^(?:Last saved by|Company|Manager|Category)\s*:.*$',
        ]

        lines = text.split('\n')
        cleaned_lines = []

        for line in lines:
            is_metadata = False
            for pattern in metadata_patterns:
                if re.match(pattern, line.strip(), re.IGNORECASE):
                    is_metadata = True
                    break

            if not is_metadata:
                cleaned_lines.append(line)

        return '\n'.join(cleaned_lines)

    def preprocess(
        self,
        text: str,
        preserve_structure: bool = True,
        aggressive_cleaning: bool = False
    ) -> str:
        """
        Main preprocessing pipeline - applies all cleaning steps

        Args:
            text: Raw text from document extraction (e.g., Tika)
            preserve_structure: If True, preserve paragraph breaks and structure
            aggressive_cleaning: If True, apply more aggressive cleaning (may remove some content)

        Returns:
            Cleaned text ready for LLM processing
        """
        if not text or len(text.strip()) == 0:
            return ""

        # Step 1: Clean Tika artifacts and control characters
        text = self.clean_tika_artifacts(text)

        # Step 2: Remove headers, footers, and page numbers
        text = self.remove_headers_footers(text)

        # Step 3: Clean table artifacts
        text = self.clean_table_artifacts(text)

        # Step 4: Remove document metadata
        text = self.clean_document_metadata(text)

        # Step 5: Normalize whitespace
        text = self.normalize_whitespace(text, preserve_paragraphs=preserve_structure)

        if aggressive_cleaning:
            # Step 6: Remove repeated content (headers/footers that appear multiple times)
            text = self.remove_repeated_content(text)

            # Step 7: Extract main content (filter very short lines)
            text = self.extract_main_content(text)

            # Step 8: Final whitespace normalization
            text = self.normalize_whitespace(text, preserve_paragraphs=preserve_structure)

        return text.strip()

    def smart_truncate(
        self,
        text: str,
        max_chars: int,
        preserve_sentences: bool = True
    ) -> str:
        """
        Intelligently truncate text to fit within character limit

        Args:
            text: Input text
            max_chars: Maximum number of characters
            preserve_sentences: If True, try to end at sentence boundaries

        Returns:
            Truncated text
        """
        if len(text) <= max_chars:
            return text

        if preserve_sentences:
            # Try to truncate at sentence boundary
            truncated = text[:max_chars]

            # Find last sentence ending (.!?) before max_chars
            sentence_end = max(
                truncated.rfind('. '),
                truncated.rfind('! '),
                truncated.rfind('? ')
            )

            if sentence_end > max_chars * 0.7:  # If we found one in the last 30%
                return truncated[:sentence_end + 1].strip()

        # Otherwise just truncate at max_chars
        return text[:max_chars].strip()

    def chunk_text(
        self,
        text: str,
        chunk_size: int = 4000,
        overlap: int = 200
    ) -> List[str]:
        """
        Split text into overlapping chunks for processing long documents

        Args:
            text: Input text
            chunk_size: Size of each chunk in characters
            overlap: Number of characters to overlap between chunks

        Returns:
            List of text chunks
        """
        if len(text) <= chunk_size:
            return [text]

        chunks = []
        start = 0

        while start < len(text):
            # Get chunk
            end = start + chunk_size
            chunk = text[start:end]

            # Try to end at paragraph break
            if end < len(text):
                last_para = chunk.rfind('\n\n')
                if last_para > chunk_size * 0.7:  # If found in last 30%
                    end = start + last_para
                    chunk = text[start:end]

            chunks.append(chunk.strip())

            # Move to next chunk with overlap
            start = end - overlap

            # Avoid infinite loop
            if start >= len(text) - overlap:
                break

        return chunks

    def get_content_summary_stats(self, text: str) -> dict:
        """
        Get statistics about the processed content

        Args:
            text: Processed text

        Returns:
            Dictionary with content statistics
        """
        lines = [l.strip() for l in text.split('\n') if l.strip()]
        words = text.split()

        return {
            'char_count': len(text),
            'word_count': len(words),
            'line_count': len(lines),
            'avg_line_length': sum(len(l) for l in lines) / len(lines) if lines else 0,
            'avg_word_length': sum(len(w) for w in words) / len(words) if words else 0,
        }


# Singleton instance for easy import
_preprocessor = DocumentPreprocessor()


def preprocess_for_llm(
    text: str,
    max_chars: int = 4000,
    aggressive_cleaning: bool = False
) -> str:
    """
    Convenience function: Preprocess and truncate text for LLM processing

    This is the main function to use for preparing document content before
    sending to LLMs for categorization, keyword extraction, or summarization.

    Args:
        text: Raw text from document extraction
        max_chars: Maximum characters to send to LLM
        aggressive_cleaning: Apply more aggressive cleaning

    Returns:
        Clean, truncated text ready for LLM
    """
    # Clean the text
    cleaned = _preprocessor.preprocess(
        text,
        preserve_structure=True,
        aggressive_cleaning=aggressive_cleaning
    )

    # Truncate intelligently
    truncated = _preprocessor.smart_truncate(cleaned, max_chars, preserve_sentences=True)

    return truncated


def preprocess_for_embedding(
    text: str,
    max_chars: int = 8000
) -> str:
    """
    Convenience function: Preprocess text for embedding generation

    Embeddings benefit from more content, so we use a higher character limit
    and preserve document structure better.

    Args:
        text: Raw text from document extraction
        max_chars: Maximum characters for embedding

    Returns:
        Clean text ready for embedding generation
    """
    # Clean with structure preservation
    cleaned = _preprocessor.preprocess(
        text,
        preserve_structure=True,
        aggressive_cleaning=False  # Less aggressive for embeddings
    )

    # Truncate with sentence preservation
    truncated = _preprocessor.smart_truncate(cleaned, max_chars, preserve_sentences=True)

    return truncated


def chunk_document_for_llm(
    text: str,
    chunk_size: int = 4000,
    overlap: int = 200,
    clean_first: bool = True
) -> List[str]:
    """
    Convenience function: Clean and chunk long documents

    Use this for processing documents that are too long to send to LLM in one go.
    Returns multiple chunks that can be processed separately.

    Args:
        text: Raw text from document extraction
        chunk_size: Size of each chunk
        overlap: Overlap between chunks to maintain context
        clean_first: Whether to clean the text before chunking

    Returns:
        List of cleaned text chunks
    """
    if clean_first:
        text = _preprocessor.preprocess(text, preserve_structure=True)

    return _preprocessor.chunk_text(text, chunk_size, overlap)


if __name__ == '__main__':
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)

    sample_text = """
    Page 1 of 10

    CONFIDENTIAL

    Document Title: Sample Report
    Author: John Doe
    Date: 01/15/2024

    ==========================================

    Introduction

    This is the first paragraph of actual content. It contains useful information
    that should be preserved during preprocessing.

    This is a second paragraph with more details about the subject matter.

    |=====================================|
    | Column 1  | Column 2    | Column 3  |
    |-----------|-------------|-----------|
    | Data 1    | Data 2      | Data 3    |
    |=====================================|

    - 2 -

    Conclusion

    Final thoughts and summary of the document.

    © Copyright 2024 Company Name. All Rights Reserved.
    """

    preprocessor = DocumentPreprocessor()

    print("=" * 60)
    print("ORIGINAL TEXT:")
    print("=" * 60)
    print(sample_text)
    print()

    print("=" * 60)
    print("PROCESSED TEXT:")
    print("=" * 60)
    processed = preprocessor.preprocess(sample_text, aggressive_cleaning=True)
    print(processed)
    print()

    print("=" * 60)
    print("STATISTICS:")
    print("=" * 60)
    stats = preprocessor.get_content_summary_stats(processed)
    for key, value in stats.items():
        print(f"{key}: {value}")
