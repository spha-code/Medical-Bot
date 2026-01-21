from src.helper import load_pdf_file, filter_to_minimal_docs, text_split, download_embeddings
from langchain_pinecone import PineconeVectorStore
from pinecone import ServerlessSpec
from pinecone import Pinecone
from dotenv import load_dotenv
import os

load_dotenv()

PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_API_KEY = os.getenv("GEMINI_API_KEY")


os.environ["PINECONE_API_KEY"] = PINECONE_API_KEY
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
os.environ["GEMINI_API_KEY"] = OPENAI_API_KEY


extracted_data = load_pdf_file("data")
minimal_docs = filter_to_minimal_docs(extracted_data)
texts_chunks = text_split(minimal_docs)

embedding = download_embeddings()

pinecone_api_key = PINECONE_API_KEY
pc = Pinecone(api_key=pinecone_api_key)

index_name = "medical-chatbot" #This creates Index in pinecone.io

if not pc.has_index(index_name):
    pc.create_index(
        name = index_name,
        dimension=384,
        metric = "cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1")
    )

# Index Container "medical-chatbot"
# Dimension: 384
# Similarity Metric: cosine (how to compare vectors)
# Location: AWS us-east-1 (eu not available in Free Tier)

index = pc.Index(index_name)

docsearch = PineconeVectorStore.from_documents(
    documents = texts_chunks,
    embedding = embedding,
    index_name = index_name
)