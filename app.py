import streamlit as st
import sqlite3
from groq import Groq
import bcrypt
from datetime import datetime
import pandas as pd
import csv
from io import StringIO

# Database setup
def init_db():
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, is_admin INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS chats
                 (id INTEGER PRIMARY KEY, user_id INTEGER, message TEXT, role TEXT, timestamp TEXT)''')
    
    # Check if admin exists, if not, create the fixed admin account
    c.execute("SELECT * FROM users WHERE username=?", ('samson tan',))
    if not c.fetchone():
        hashed_password = bcrypt.hashpw('117853'.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                  ('samson tan', hashed_password, 1))
    
    conn.commit()
    conn.close()

# User authentication
def authenticate(username, password):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
        return user
    return None

# User registration (for regular users only)
def register_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
                  (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

# Save chat message
def save_chat_message(user_id, message, role):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute("INSERT INTO chats (user_id, message, role, timestamp) VALUES (?, ?, ?, ?)",
              (user_id, message, role, timestamp))
    conn.commit()
    conn.close()

# Get user's chat history
def get_user_chats(user_id):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("SELECT message, role FROM chats WHERE user_id=? ORDER BY timestamp", (user_id,))
    chats = c.fetchall()
    conn.close()
    return [{"role": role, "content": message} for message, role in chats]

# Get all chats (for admin)
def get_all_chats():
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("SELECT users.username, chats.message, chats.role, chats.timestamp FROM chats JOIN users ON chats.user_id = users.id ORDER BY chats.timestamp")
    chats = c.fetchall()
    conn.close()
    return chats

# Initialize Groq client
def init_groq_client():
    try:
        api_key = st.secrets["GROQ_API_KEY"]
        return Groq(api_key=api_key)
    except Exception as e:
        st.error(f"Error initializing Groq client: {str(e)}")
        return None

# Streamlit app
def main():
    st.title("CPDI Q&A App")
    
    init_db()

    if 'user' not in st.session_state:
        st.session_state.user = None

    if st.session_state.user is None:
        choice = st.selectbox("Login/Signup", ["Login", "Sign Up"])
        
        if choice == "Login":
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                user = authenticate(username, password)
                if user:
                    st.session_state.user = user
                    st.success("Logged in successfully")
                    st.experimental_rerun()
                else:
                    st.error("Invalid username or password")
        
        elif choice == "Sign Up":
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            
            if st.button("Sign Up"):
                if new_username == 'samson tan':
                    st.error("This username is reserved. Please choose a different username.")
                elif register_user(new_username, new_password):
                    st.success("Account created successfully. Please log in.")
                else:
                    st.error("Username already exists")
    
    else:
        st.write(f"Welcome, {st.session_state.user[1]}!")
        if st.button("Logout"):
            st.session_state.user = None
            st.experimental_rerun()

        if st.session_state.user[3]:  # Admin view
            st.subheader("Admin View - All Chats")
            all_chats = get_all_chats()
            for username, message, role, timestamp in all_chats:
                st.text(f"{username} ({timestamp}): {role} - {message}")
        
        else:  # Regular user view
            st.subheader("Your Chat")
            user_chats = get_user_chats(st.session_state.user[0])
            for chat in user_chats:
                with st.chat_message(chat["role"]):
                    st.markdown(chat["content"])

            user_question = st.chat_input("Ask a question:")
            if user_question:
                save_chat_message(st.session_state.user[0], user_question, "user")
                with st.chat_message("user"):
                    st.markdown(user_question)

                client = init_groq_client()
                if client:
                    try:
                        with st.chat_message("assistant"):
                            message_placeholder = st.empty()
                            full_response = ""
                            stream = client.chat.completions.create(
                                messages=[
                                    {"role": "system", "content": "You are a helpful assistant."},
                                    *user_chats,
                                    {"role": "user", "content": user_question}
                                ],
                                model="mixtral-8x7b-32768",
                                max_tokens=1024,
                                stream=True
                            )
                            for chunk in stream:
                                if chunk.choices[0].delta.content is not None:
                                    full_response += chunk.choices[0].delta.content
                                    message_placeholder.markdown(full_response + "▌")
                            
                            message_placeholder.markdown(full_response)
                        save_chat_message(st.session_state.user[0], full_response, "assistant")
                    except Exception as e:
                        st.error(f"An error occurred while processing your request: {str(e)}")

# Modified get_all_chats function to return a DataFrame
def get_all_chats():
    conn = sqlite3.connect('chat_app.db')
    query = """
    SELECT users.username, chats.message, chats.role, chats.timestamp 
    FROM chats 
    JOIN users ON chats.user_id = users.id 
    ORDER BY chats.timestamp
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# New function to convert DataFrame to CSV
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# Streamlit app
def main():
    st.title("CPDI Q&A App")
    
    init_db()

    if 'user' not in st.session_state:
        st.session_state.user = None

    if st.session_state.user is None:
        choice = st.selectbox("Login/Signup", ["Login", "Sign Up"])
        
        if choice == "Login":
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                user = authenticate(username, password)
                if user:
                    st.session_state.user = user
                    st.success("Logged in successfully")
                    st.experimental_rerun()
                else:
                    st.error("Invalid username or password")
        
        elif choice == "Sign Up":
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            
            if st.button("Sign Up"):
                if new_username == 'samson tan':
                    st.error("This username is reserved. Please choose a different username.")
                elif register_user(new_username, new_password):
                    st.success("Account created successfully. Please log in.")
                else:
                    st.error("Username already exists")
    
    else:
        st.write(f"Welcome, {st.session_state.user[1]}!")
        if st.button("Logout"):
            st.session_state.user = None
            st.experimental_rerun()

        if st.session_state.user[3]:  # Admin view
            st.subheader("Admin View - All Chats")
            all_chats_df = get_all_chats()
            
            # Display chats in the Streamlit app
            st.dataframe(all_chats_df)
            
            # Add a download button
            csv = convert_df_to_csv(all_chats_df)
            st.download_button(
                label="Download chat logs as CSV",
                data=csv,
                file_name="chat_logs.csv",
                mime="text/csv",
            )
        
        else:  # Regular user view
            st.subheader("Your Chat")
            user_chats = get_user_chats(st.session_state.user[0])
            for chat in user_chats:
                with st.chat_message(chat["role"]):
                    st.markdown(chat["content"])

            user_question = st.chat_input("Ask a question:")
            if user_question:
                save_chat_message(st.session_state.user[0], user_question, "user")
                with st.chat_message("user"):
                    st.markdown(user_question)

                client = init_groq_client()
                if client:
                    try:
                        with st.chat_message("assistant"):
                            message_placeholder = st.empty()
                            full_response = ""
                            stream = client.chat.completions.create(
                                messages=[
                                    {"role": "system", "content": "You are a helpful assistant."},
                                    *user_chats,
                                    {"role": "user", "content": user_question}
                                ],
                                model="mixtral-8x7b-32768",
                                max_tokens=1024,
                                stream=True
                            )
                            for chunk in stream:
                                if chunk.choices[0].delta.content is not None:
                                    full_response += chunk.choices[0].delta.content
                                    message_placeholder.markdown(full_response + "▌")
                            
                            message_placeholder.markdown(full_response)
                        save_chat_message(st.session_state.user[0], full_response, "assistant")
                    except Exception as e:
                        st.error(f"An error occurred while processing your request: {str(e)}")

if __name__ == "__main__":
    main()
