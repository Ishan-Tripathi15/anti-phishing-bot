import json
import os
import re
from urllib.parse import urlparse
from knowledge import retrieve_context

try:
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_mistralai import ChatMistralAI
except Exception:
    ChatPromptTemplate = None
    ChatMistralAI = None

SHORTENERS={"bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rb.gy"}
SUSPICIOUS_TLDS={"zip","mov","click","top","work","gq","tk","ml","cf"}
URL_TERMS={"login","verify","verification","secure","account","update","password","wallet","payment","signin"}
EMAIL_TERMS={"urgent","immediately","verify","suspended","password","account","click here","confirm","login","payment","invoice","gift card","security alert","limited time"}

def url_features(url):
    p=urlparse(url if "://" in url else "http://"+url)
    host=(p.hostname or "").lower(); text=p.geturl().lower(); signals=[]; score=0
    if p.scheme!="https": signals.append("URL does not use HTTPS"); score+=12
    if "@" in p.netloc: signals.append("Uses @ in the authority component"); score+=25
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}",host): signals.append("Uses an IP address instead of a domain"); score+=25
    if host.count(".")>=3: signals.append("Unusually deep subdomain structure"); score+=10
    if len(url)>100: signals.append("Unusually long URL"); score+=8
    if host in SHORTENERS: signals.append("Uses a URL-shortening service"); score+=15
    tld=host.rsplit(".",1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS: signals.append("High-risk or suspicious TLD pattern: ."+tld); score+=12
    matched=sorted(x for x in URL_TERMS if x in text)
    if matched: signals.append("Credential/account-themed URL terms: "+", ".join(matched)); score+=min(20,len(matched)*5)
    if host.count("-")>=3: signals.append("Multiple hyphens in hostname"); score+=8
    return min(score,100),signals,{"scheme":p.scheme,"hostname":host,"path":p.path,"length":len(url)}

def email_features(subject,body):
    text=(subject+"\n"+body).lower(); signals=[]; score=0
    for term in sorted(EMAIL_TERMS):
        if term in text: signals.append("Suspicious language: '"+term+"'"); score+=6
    if re.search(r"https?://",text): signals.append("Contains one or more links"); score+=8
    if re.search(r"\b(?:password|otp|one[- ]time password|cvv|card number)\b",text): signals.append("Requests or references sensitive credentials"); score+=25
    if re.search(r"\b(?:wire|gift card|crypto|payment)\b",text): signals.append("Financial/payment-related request"); score+=18
    if re.search(r"\b(?:click|tap)\b.{0,50}\b(?:link|here)\b",text,re.I|re.S): signals.append("Call-to-action urging the recipient to click"); score+=12
    return min(score,100),list(dict.fromkeys(signals))

def fallback(score,signals,context,kind):
    if score>=70: verdict="High-risk phishing"; recommendation="Do not click links, submit credentials, or send money. Verify through an independently known official channel."
    elif score>=40: verdict="Suspicious"; recommendation="Treat with caution and verify the sender or domain through a trusted channel before acting."
    else: verdict="Low-risk / no strong phishing indicators"; recommendation="No strong indicators were detected, but continue to verify unexpected requests."
    return {"risk_score":score,"verdict":verdict,"signals":signals or ["No strong heuristic indicators detected"],"recommendation":recommendation,"explanation":("Signals detected: "+"; ".join(signals)+"." if signals else "No strong heuristic indicators were detected."),"model":"Mistral-7B-Instruct (optional) / fallback","mode":"fallback","retrieved_context":context}

def mistral(kind,content,base_score,signals,context):
    key=os.getenv("MISTRAL_API_KEY")
    if not key or ChatMistralAI is None or ChatPromptTemplate is None: return None
    model=os.getenv("MISTRAL_MODEL","open-mistral-7b")
    prompt=ChatPromptTemplate.from_messages([("system","You are a defensive cybersecurity analyst. Return ONLY JSON with risk_score, verdict, signals, explanation, recommendation. Do not provide attack instructions or credential-collection guidance."),("human","Type: {kind}\nInput: {content}\nHeuristic score: {score}\nSignals: {signals}\nSecurity context: {context}")])
    response=(prompt | ChatMistralAI(model=model,temperature=0,api_key=key)).invoke({"kind":kind,"content":content,"score":base_score,"signals":"\n".join(signals),"context":context})
    raw=response.content if hasattr(response,"content") else str(response)
    raw=re.sub(r"^```(?:json)?\s*|\s*```$","",raw.strip(),flags=re.I)
    data=json.loads(raw); data["risk_score"]=max(0,min(100,int(data["risk_score"])))
    data["model"]=model; data["mode"]="mistral"; data["retrieved_context"]=context
    return data

def analyze_url(url):
    score,signals,meta=url_features(url); context=retrieve_context("URL phishing "+" ".join(signals))
    return mistral("URL",url+"\nMetadata: "+str(meta),score,signals,context) or fallback(score,signals,context,"URL")

def analyze_email(subject,body):
    score,signals=email_features(subject,body); context=retrieve_context("email phishing "+" ".join(signals))
    return mistral("Email","Subject: "+subject+"\n\nBody:\n"+body,score,signals,context) or fallback(score,signals,context,"email")
