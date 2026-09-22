"""
test_pipeline_prototype.py
Experimenting with contextual features, negation propagation, diverse ham, and threshold optimization.
"""
import re
import string
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

NEGATION_TERMS = {
    "no", "not", "never", "none", "neither", "nor", "cannot", "cant", "wont",
    "dont", "doesnt", "didnt", "isnt", "arent", "wasnt", "werent", "hardly", "scarcely", "without"
}

STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", 
    "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", 
    "but", "by", "could", "did", "do", "does", "doing", "down", "during", "each", "few", "for", 
    "from", "further", "had", "has", "have", "having", "he", "her", "here", "hers", "herself", 
    "him", "himself", "his", "how", "i", "if", "in", "into", "is", "it", "its", "itself", 
    "me", "more", "most", "my", "myself", "of", "off", "on", "once", "only", "or", "other", 
    "ought", "our", "ours", "ourselves", "out", "over", "own", "same", "she", "should", "so", 
    "some", "such", "than", "that", "the", "their", "theirs", "them", "themselves", "then", 
    "there", "these", "they", "this", "those", "through", "to", "too", "under", "until", "up", 
    "very", "was", "we", "were", "what", "when", "where", "which", "while", "who", "whom", 
    "why", "with", "you", "your", "yours", "yourself", "yourselves"
}

def clean_text_advanced(text: str) -> str:
    if not text or not isinstance(text, str):
        return ""
    
    t = text.lower()
    
    # 1. URLs separately
    t = re.sub(r"https?://\S+|www\.\S+", " url_token ", t)
    
    # 2. Email addresses separately
    t = re.sub(r"\S+@\S+", " email_token ", t)
    
    # 3. Currency / Monetary numbers (e.g. $500, £1000)
    t = re.sub(r"[\$£€]\s*\d+(?:[,\.]\d+)?", " currency_amount ", t)
    
    # 4. Phone numbers / long reference numbers
    t = re.sub(r"\b\d{4,}\b", " num_sequence ", t)
    
    # 5. Regular numbers
    t = re.sub(r"\b\d+\b", " num_token ", t)
    
    # 6. Normalize repeated characters (e.g., loooool -> lool, freeeee -> free)
    t = re.sub(r"(.)\1{2,}", r"\1\1", t)
    
    # 7. Normalize contractions
    t = t.replace("n't", " not").replace("'re", " are").replace("'s", " is").replace("'d", " would")
    t = t.replace("'ll", " will").replace("'ve", " have").replace("'m", " am")
    
    # 8. Tokenize keeping punctuation marks as boundary markers for negation
    raw_tokens = re.findall(r"[a-zA-Z_]+|[.,!?;:\n]", t)
    
    processed_tokens = []
    negate_active = False
    negate_window = 0
    
    for tok in raw_tokens:
        if tok in ".,!?;:\n":
            negate_active = False
            negate_window = 0
            continue
        
        clean_tok = tok.strip()
        if not clean_tok:
            continue
            
        if clean_tok in NEGATION_TERMS:
            negate_active = True
            negate_window = 4  # apply not_ prefix to next 4 words in same clause
            processed_tokens.append("not")
            continue
            
        if negate_active and negate_window > 0:
            processed_tokens.append(f"not_{clean_tok}")
            negate_window -= 1
            if negate_window == 0:
                negate_active = False
        else:
            if clean_tok not in STOPWORDS or clean_tok in {"urgent", "alert", "security", "verify", "claim", "free", "payment", "winner"}:
                processed_tokens.append(clean_tok)
                
    return " ".join(processed_tokens)

print("Testing cleaner:")
print("Ex 1:", clean_text_advanced("Security Alert: We detected a new login. We will never ask you to provide your password or verify your account."))
print("Ex 2:", clean_text_advanced("Urgent! Verify your account immediately to claim your $1000 reward now!"))
print("Ex 3:", clean_text_advanced("No payment is required. Do not click any unknown links."))
