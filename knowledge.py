from pathlib import Path
import re

KNOWLEDGE=Path(__file__).parent/"data"/"security_knowledge.txt"

def retrieve_context(query,k=3):
    chunks=[x.strip() for x in re.split(r"\n\s*\n",KNOWLEDGE.read_text(encoding="utf-8")) if x.strip()]
    q=set(re.findall(r"[a-z0-9]+",query.lower()))
    ranked=[]
    for c in chunks:
        words=set(re.findall(r"[a-z0-9]+",c.lower())); ranked.append((len(q&words),c))
    ranked.sort(reverse=True,key=lambda x:x[0])
    return "\n\n".join(c for _,c in ranked[:k])
