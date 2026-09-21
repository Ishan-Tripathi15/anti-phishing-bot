from pathlib import Path
import re
import os
import math

KNOWLEDGE=Path(__file__).parent/"data"/"security_knowledge.txt"

def _chunks():
    return [x.strip() for x in re.split(r"\n\s*\n", KNOWLEDGE.read_text(encoding="utf-8")) if x.strip()]

def _cosine(a,b):
    dot=sum(x*y for x,y in zip(a,b))
    na=math.sqrt(sum(x*x for x in a)); nb=math.sqrt(sum(x*x for x in b))
    return dot/(na*nb) if na and nb else 0.0

def _embedding_retrieve(query,chunks,k):
    try:
        from langchain_mistralai import MistralAIEmbeddings
        key=os.getenv("MISTRAL_API_KEY")
        if not key:
            return None
        embeddings=MistralAIEmbeddings(model=os.getenv("MISTRAL_EMBEDDING_MODEL","mistral-embed"),api_key=key)
        vectors=embeddings.embed_documents(chunks)
        q=embeddings.embed_query(query)
        ranked=sorted(zip(vectors,chunks),key=lambda x:_cosine(q,x[0]),reverse=True)
        return "\n\n".join(c for _,c in ranked[:k])
    except Exception:
        return None

def retrieve_context(query,k=3):
    chunks=_chunks()
    semantic=_embedding_retrieve(query,chunks,k)
    if semantic:
        return semantic
    q=set(re.findall(r"[a-z0-9]+",query.lower()))
    ranked=[]
    for c in chunks:
        words=set(re.findall(r"[a-z0-9]+",c.lower()))
        ranked.append((len(q&words),c))
    ranked.sort(reverse=True,key=lambda x:x[0])
    return "\n\n".join(c for _,c in ranked[:k])
