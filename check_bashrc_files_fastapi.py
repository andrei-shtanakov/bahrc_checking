from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import torch
from transformers import AutoTokenizer, AutoModel
import re

app = FastAPI(
    title="Bashrc Analyzer",
    description="API for analyzing .bashrc files for potentially dangerous patterns",
    version="1.0.0",
)

# Loading the model and tokenizer
tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
model = AutoModel.from_pretrained("microsoft/codebert-base")


class BashrcInput(BaseModel):
    content: str


def get_embedding(text):
    inputs = tokenizer(
        text, return_tensors="pt", truncation=True, max_length=512, padding=True
    )
    with torch.no_grad():
        outputs = model(**inputs)
    return outputs.last_hidden_state.mean(dim=1)


def categorize_bashrc(file_content):
    categories = {
        "environment_vars": [],
        "module_loads": [],
        "path_modifications": [],
        "libraries": [],
        "conda": [],
    }

    lines = file_content.split("\n")
    current_function = None

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "export LD_LIBRARY_PATH" in line:
            categories["libraries"].append(line)
        elif "export PYTHON_PATH" in line:
            categories["environment_vars"].append(line)
        elif "export PATH=" in line:
            categories["path_modifications"].append(line)
        elif "module load" in line or "ml " in line:
            categories["module_loads"].append(line)
        elif "conda initialize" in line or "__conda_setup" in line:
            categories["conda"].append(line)

    return categories


def analyze_category(category, category_content, incorrect_examples, threshold=0.9):
    anomalies = []
    category_text = "\n".join(category_content)
    category_emb = get_embedding(category_text)

    incorrect_category_examples = incorrect_examples.get(category, [])
    incorrect_embeddings = [get_embedding(ex) for ex in incorrect_category_examples]

    if incorrect_embeddings:
        max_similarity = max(
            torch.cosine_similarity(category_emb, inc_emb, dim=1).item()
            for inc_emb in incorrect_embeddings
        )

        if max_similarity > threshold:
            anomalies.append((category_text, max_similarity))

    return anomalies


def analyze_bashrc(file_content, incorrect_examples, threshold=0.8):
    categories = categorize_bashrc(file_content)
    all_anomalies = {}

    for category, content in categories.items():
        if content:
            anomalies = analyze_category(
                category, content, incorrect_examples, threshold
            )
            if anomalies:
                all_anomalies[category] = anomalies

    return all_anomalies


incorrect_examples = {
    "environment_vars": [
        "PYTHON_PATH=",
        "export PYTHON_PATH=",
        "export PYTHON_PATH=$PYTHON_PATH",
        "export PYTHON_PATH=$PYTHON_PATH:/usr/prog/",
        "export PYTHON_PATH=/usr/local/lib/python3.9/site-packages",
    ],
    "module_loads": [
        "module load ",
        "module load python 3.9",
        "module load Schrodinger/2024",
        "ml Conda/24.01",
        "ml CUDA/12.1",
    ],
    "path_modifications": [
        "=/usr/prog/",
        "export PATH=$PATH;/usr/prog",
        "export PATH=/usr/prog:$PATH",
        "PATH=/usr/prog",
    ],
    "libraries": [
        "export LIBRARY_PATH=",
        "export LD_LIBRARY_PATH=/usr/lib64",
        "export LD_LIBRARY_PATH=/usr/local/lib/python3.9/site-packages",
    ],
    "conda": [
        "__conda_setup=",
        "conda activate base",
        "source activate base",
        "conda init bash",
    ],
}


@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html>
        <head>
            <title>Bashrc File Analyzer</title>
        </head>
        <body>
            <h1>Welcome to the .bashrc File Analyzer API</h1>
            <form action="/analyze_bashrc/" enctype="multipart/form-data" method="post">
                <input name="file" type="file" accept=".bashrc,text/plain">
                <input type="submit">
            </form>
        </body>
    </html>
    """


@app.post("/analyze_bashrc/", response_class=HTMLResponse)
async def analyze_bashrc_endpoint(file: UploadFile = File(...)):
    try:
        content = await file.read()
        bashrc_content = content.decode()
        anomalies = analyze_bashrc(bashrc_content, incorrect_examples)

        # Formatting results in HTML
        html_result = f"""
        <html>
            <head>
                <title>Analysis Results for {file.filename}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    pre {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <h1>Analysis Results for file {file.filename}</h1>
        """

        if anomalies:
            for category, category_anomalies in anomalies.items():
                html_result += f"<h2>Category: {category}</h2>"
                for content, similarity in category_anomalies:
                    html_result += f"""
                    <h3>Similarity: {similarity:.2f}</h3>
                    <pre>{content}</pre>
                    """
        else:
            html_result += "<p>No anomalies detected.</p>"

        html_result += """
            </body>
        </html>
        """

        return HTMLResponse(content=html_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
