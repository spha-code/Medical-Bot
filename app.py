from flask import Flask, render_template, jsonify, request
from src.helper import download_embeddings
from langchain_pinecone import PineconeVectorStore

from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI

from langchain_classic.chains.retrieval import create_retrieval_chain
from langchain_classic.chains.combine_documents import create_stuff_documents_chain


from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv
from src.prompt import *
import os

#Flask initialization
app = Flask(__name__)

load_dotenv()

PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

os.environ["PINECONE_API_KEY"] = PINECONE_API_KEY
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY

embedding = download_embeddings()

index_name = "medical-chatbot" #This creates an Index in pinecone.io

docsearch = PineconeVectorStore.from_existing_index(
    index_name = index_name,
    embedding = embedding
)


retriever = docsearch.as_retriever(search_type="similarity", search_kwargs={"k" : 3})

llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", google_api_key=GEMINI_API_KEY)

prompt = ChatPromptTemplate.from_messages([
    ("system", system_prompt), #sytem prompt given above
    ("human", "{input}") #human input through chatbot
])

question_answer_chain = create_stuff_documents_chain(llm, prompt)
rag_chain = create_retrieval_chain(retriever, question_answer_chain)

@app.route("/")
def index():
    return render_template('chat.html')

@app.route("/get", methods=["GET", "POST"])
def chat():
    msg = request.form["msg"]
    input = msg
    print(input)
    response = rag_chain.invoke({"input": msg})
    print("Response : ", response["answer"])
    return str(response["answer"])

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug = True)






