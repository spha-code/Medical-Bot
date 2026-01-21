from flask import Flask, render_template, jsonify, request
from src.helper import download_embeddings
from langchain_pinecone import PineconeVectorStore
from langchain_google_genai import ChatGoogleGenerativeAI

from langchain_classic.chains.retrieval import create_retrieval_chain
from langchain_classic.chains.combine_documents import create_stuff_documents_chain
from langchain_classic.chains.history_aware_retriever import create_history_aware_retriever

from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_community.chat_message_histories import ChatMessageHistory 
from dotenv import load_dotenv
from src.prompt import *
import os

app = Flask(__name__)
load_dotenv()

# Fixed Key Assignments
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

os.environ["PINECONE_API_KEY"] = PINECONE_API_KEY
os.environ["GOOGLE_API_KEY"] = GEMINI_API_KEY 

embedding = download_embeddings()
index_name = "medical-chatbot"

docsearch = PineconeVectorStore.from_existing_index(
    index_name=index_name,
    embedding=embedding
)

retriever = docsearch.as_retriever(search_type="similarity", search_kwargs={"k": 3})

# Initialize LLM
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.3)

# Initialize Session Memory
# Note: This is stored in server RAM. Restarting the server clears memory.
chat_history_store = ChatMessageHistory()

# --- 1. CONTEXTUALIZE QUESTION PROMPT ---
# This re-phrases the user's question to be "standalone" based on history
contextualize_q_system_prompt = (
    "Given a chat history and the latest user question "
    "which might reference context in the chat history, "
    "formulate a standalone question which can be understood "
    "without the chat history. Do NOT answer the question, "
    "just reformulate it if needed and otherwise return it as is."
)

contextualize_q_prompt = ChatPromptTemplate.from_messages([
    ("system", contextualize_q_system_prompt),
    MessagesPlaceholder("chat_history"),
    ("human", "{input}"),
])

history_aware_retriever = create_history_aware_retriever(
    llm, retriever, contextualize_q_prompt
)

# --- 2. ANSWER PROMPT ---
qa_prompt = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    MessagesPlaceholder("chat_history"),
    ("human", "{input}"),
])

# Build the Chains
question_answer_chain = create_stuff_documents_chain(llm, qa_prompt)
rag_chain = create_retrieval_chain(history_aware_retriever, question_answer_chain)


@app.route("/")
def index():
    return render_template('chat.html')


@app.route("/get", methods=["POST"])
def chat():
    msg = request.form["msg"]
    try:
        # Attempt the RAG chain
        response = rag_chain.invoke({
            "input": msg, 
            "chat_history": chat_history_store.messages
        })
        
        # Save to history
        chat_history_store.add_user_message(msg)
        chat_history_store.add_ai_message(response["answer"])
        
        return str(response["answer"])

    except Exception as e:
        # Check if it's a Quota error
        if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
            return "I'm a bit overwhelmed with requests right now! Please wait about 30-60 seconds and try again."
        
        print(f"Error occurred: {e}")
        return "Sorry, I encountered an internal error. Please try again later."


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True)