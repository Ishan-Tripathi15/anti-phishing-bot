# Anti-Phishing Bot

AI-assisted phishing detection for URLs and email content using **Mistral-7B-Instruct**, **LangChain**, and security-knowledge vector retrieval.

## Features
- URL feature engineering for HTTPS, IP hosts, deep subdomains, URL shorteners, suspicious TLDs and credential-themed paths.
- Email analysis for urgency, credential requests, payment pressure and suspicious links.
- LangChain prompt pipeline with optional Mistral-7B-Instruct inference.
- Security-knowledge retrieval layer for context-aware analysis.
- Explainable risk score, signals, recommendation and technical context.
- Streamlit interface.
- Automated tests and Docker support.

## Run

    pip install -r requirements.txt
    streamlit run app.py

The demo works without a key. For Mistral-backed analysis set MISTRAL_API_KEY and optionally MISTRAL_MODEL.

## Architecture

    URL / Email -> Feature Engineering -> Security Knowledge Retrieval -> LangChain -> Mistral-7B-Instruct -> Risk + Explanation

## Resume bullets

- Developed a phishing detection system using Mistral-7B Instruct to analyse URLs and email content for malicious patterns.
- Leveraged LangChain and vector embeddings for context-aware threat detection.
- Showcased practical integration of AI, LLMs, and cybersecurity feature engineering for real-world security applications.

## Security

Never commit API keys or real credentials. Use the application only for defensive analysis.
