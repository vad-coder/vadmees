from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Form, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from cryptography.fernet import Fernet
import bcrypt
import jwt
import json
from typing import List, Dict
import os
from datetime import datetime, timedelta

app = FastAPI()

# Подключение папки app как статической для раздачи HTML, CSS, JavaScript
app.mount("/app", StaticFiles(directory="app"), name="app")

clients: Dict[str, List[WebSocket]] = {
    "general": [],
    "help": []
}

friend_requests: Dict[str, List[str]] = {}
friends: Dict[str, List[str]] = {}
active_users: Dict[str, bool] = {}

# Генерация ключа для шифрования
key_file = "secret.key"
if not os.path.exists(key_file):
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
else:
    with open(key_file, "rb") as f:
        key = f.read()

cipher_suite = Fernet(key)

# JWT секретный ключ
JWT_SECRET = "your_jwt_secret"  # Замените на ваш собственный секрет
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600  # Время жизни токена в секундах

def create_jwt_token(username: str):
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Токен истёк")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный токен")

@app.get("/")
async def get_main_messenger_page():
    with open("app/messenger.html", "r", encoding="utf-8") as file:
        html_content = file.read()
    return HTMLResponse(content=html_content)

@app.get("/register")
async def get_registration_page():
    with open("app/registration_custom.html", "r", encoding="utf-8") as file:
        html_content = file.read()
    return HTMLResponse(content=html_content)

@app.post("/register")
async def register_user(
    email: str = Form(...), 
    username: str = Form(...), 
    password: str = Form(...), 
    day: str = Form(...), 
    month: str = Form(...), 
    year: str = Form(...)
):
    user_data = {
        "email": email,
        "username": username,
        "password": bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        "birthdate": f"{day}-{month}-{year}"
    }
    
    encrypted_data = cipher_suite.encrypt(json.dumps(user_data).encode())
    
    with open(users_file, "ab") as f:
        f.write(encrypted_data + b"\n")
    
    friend_requests[username] = []
    friends[username] = []
    
    return RedirectResponse(url="/login", status_code=303)

@app.get("/login")
async def get_login_page():
    with open("app/login_custom.html", "r", encoding="utf-8") as file:
        html_content = file.read()
    return HTMLResponse(content=html_content)

@app.post("/login")
async def login_user(email: str = Form(...), password: str = Form(...)):
    try:
        with open(users_file, "rb") as f:
            for line in f:
                decrypted_data = json.loads(cipher_suite.decrypt(line.strip()).decode())
                if decrypted_data["email"] == email and bcrypt.checkpw(password.encode('utf-8'), decrypted_data["password"].encode('utf-8')):
                    username = decrypted_data["username"]
                    token = create_jwt_token(username)
                    return RedirectResponse(url=f"/messenger?token={token}", status_code=303)
    except FileNotFoundError:
        pass
    
    return JSONResponse(content={"message": "Неверный email или пароль"}, status_code=400)

@app.get("/messenger")
async def get_messenger_page(token: str = Depends(verify_jwt_token)):
    with open("app/messenger.html", "r", encoding="utf-8") as file:
        html_content = file.read()
    return HTMLResponse(content=html_content)

@app.post("/add_friend")
async def add_friend_request(token: str = Depends(verify_jwt_token), username: str = Form(...), friend_username: str = Form(...)):
    if friend_username in friend_requests:
        friend_requests[friend_username].append(username)
        return JSONResponse(content={"message": f"Заявка в друзья отправлена пользователю {friend_username}"})
    return JSONResponse(content={"message": "Пользователь не найден"}, status_code=404)

@app.get("/friend_requests/{username}")
async def get_friend_requests(username: str, token: str = Depends(verify_jwt_token)):
    if username in friend_requests:
        return JSONResponse(content={"friend_requests": friend_requests[username]})
    return JSONResponse(content={"message": "Пользователь не найден"}, status_code=404)

@app.post("/handle_friend_request")
async def handle_friend_request(token: str = Depends(verify_jwt_token), username: str = Form(...), requester: str = Form(...), action: str = Form(...)):
    if action == "accept":
        if username in friend_requests and requester in friend_requests[username]:
            friend_requests[username].remove(requester)
            friends[username].append(requester)
            friends[requester].append(username)
            return JSONResponse(content={"message": f"Вы приняли заявку в друзья от {requester}"})
    elif action == "decline":
        if username in friend_requests and requester in friend_requests[username]:
            friend_requests[username].remove(requester)
            return JSONResponse(content={"message": f"Вы отклонили заявку в друзья от {requester}"})
    return JSONResponse(content={"message": "Некорректный запрос"}, status_code=400)

@app.get("/friends/{username}")
async def get_friends(username: str, token: str = Depends(verify_jwt_token)):
    if username in friends:
        return JSONResponse(content={"friends": friends[username]})
    return JSONResponse(content={"message": "Пользователь не найден"}, status_code=404)

@app.post("/send_dm")
async def send_direct_message(token: str = Depends(verify_jwt_token), sender: str = Form(...), receiver: str = Form(...), message: str = Form(...)):
    if receiver in friends.get(sender, []):
        return JSONResponse(content={"message": f"Сообщение отправлено пользователю {receiver}"})
    return JSONResponse(content={"message": "Пользователь не является вашим другом"}, status_code=403)

@app.websocket("/ws/{channel_name}")
async def websocket_endpoint(websocket: WebSocket, channel_name: str):
    await websocket.accept()
    if channel_name not in clients:
        clients[channel_name] = []
    clients[channel_name].append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            for client in clients[channel_name]:
                if client != websocket:
                    await client.send_text(data)
    except WebSocketDisconnect:
        clients[channel_name].remove(websocket)
        if len(clients[channel_name]) == 0:
            del clients[channel_name]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="26.227.105.170", port=8000)  # Используйте ваш IP-адрес
