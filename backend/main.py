from fastapi import FastAPI, UploadFile, File

app = FastAPI()

@app.get("/")
def root():
    return {"status": "NET-WATCH alive"}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    contents = await file.read()  # reads the raw bytes of the file
    return {
        "filename": file.filename,
        "size": len(contents),
        "content_type": file.content_type
    }
