from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse

app = FastAPI()


@app.get("/")
async def root():
    #return {"message": "Авторелоад действительно работает"}
    return FileResponse('start.html')