from langchain_community.document_loaders import PyPDFLoader, DirectoryLoader
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter   # <- add this
from langchain_huggingface import HuggingFaceEmbeddings
from typing import List

def load_pdf_file(data):
    loader = DirectoryLoader(data,
                             glob="*.pdf",
                             loader_cls=PyPDFLoader)
    
    document=loader.load()

    return document

def filter_to_minimal_docs(docs: List[Document]) -> List[Document]:
    """"
    Given a list of documents, return a new list of Document objects
    containing only 'source' in metadata and the original page_content.
    """                           
                        
    minimal_docs: List[Document] = []
    for doc in docs:
        src = doc.metadata.get("source")
        minimal_docs.append(
            Document(
            page_content=doc.page_content,
            metadata={"source": src}
            )
        )
    return minimal_docs

def text_split(minimal_docs):
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=20,
        length_function=len
    )
    return text_splitter.split_documents(minimal_docs)

def download_embeddings():
    embeddings = HuggingFaceEmbeddings(
        model_name="ibm-granite/granite-embedding-small-english-r2"
    )
    return embeddings

