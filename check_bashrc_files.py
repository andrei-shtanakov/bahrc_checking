import re
import torch
from transformers import AutoTokenizer, AutoModel

tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
model = AutoModel.from_pretrained("microsoft/codebert-base")

def get_embedding(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
    return outputs.last_hidden_state.mean(dim=1)

def categorize_bashrc(file_content):
    categories = {
        'environment_vars': [],
        'aliases': [],
        'functions': [],
        'module_loads': [],
        'path_modifications': [],
        'other': []
    }
    
    lines = file_content.split('\n')
    current_function = None
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if line.startswith('export '):
            if 'PATH' in line:
                categories['path_modifications'].append(line)
            else:
                categories['environment_vars'].append(line)
        elif line.startswith('alias '):
            categories['aliases'].append(line)
        elif line.startswith('function ') or line.endswith(' () {'):
            current_function = line
        elif current_function:
            if line == '}':
                categories['functions'].append(current_function)
                current_function = None
            else:
                current_function += '\n' + line
        elif 'module load' in line or 'source' in line:
            categories['module_loads'].append(line)
        else:
            categories['other'].append(line)
    
    return categories

def analyze_category(category_content, incorrect_examples, threshold=0.8):
    anomalies = []
    category_text = '\n'.join(category_content)
    category_emb = get_embedding(category_text)
    
    incorrect_embeddings = [get_embedding(ex) for ex in incorrect_examples]
    
    max_similarity = max(torch.cosine_similarity(category_emb, inc_emb, dim=1).item() 
                         for inc_emb in incorrect_embeddings)
    
    if max_similarity > threshold:
        anomalies.append((category_text, max_similarity))
    
    return anomalies

def analyze_bashrc(file_content, incorrect_examples, threshold=0.8):
    categories = categorize_bashrc(file_content)
    all_anomalies = {}
    
    for category, content in categories.items():
        if content:
            anomalies = analyze_category(content, incorrect_examples, threshold)
            if anomalies:
                all_anomalies[category] = anomalies
    
    return all_anomalies

# Пример использования
incorrect_examples = [
    "export PATH=/usr/bin",
    "alias rm='rm -rf /'",
    "function delete_all() { rm -rf /; }",
    "module load malicious_module",
    "export EDITOR='vim && echo pwned >> ~/.bashrc'"
]

bashrc_content = """
# Set environment variables
export PATH=$PATH:/usr/local/bin
export EDITOR=vim

# Aliases
alias ll='ls -la'
alias grep='grep --color=auto'

# Functions
function update_system() {
    sudo apt update && sudo apt upgrade -y
}

# Load modules
source ~/.bash_profile
module load python/3.9

# Other
echo "Welcome to the system!"

# Potentially problematic line
alias delete='rm -rf /'
"""

anomalies = analyze_bashrc(bashrc_content, incorrect_examples)

print("Анализ .bashrc файла:")
if anomalies:
    print("Обнаружены аномалии:")
    for category, category_anomalies in anomalies.items():
        print(f"\nКатегория: {category}")
        for content, similarity in category_anomalies:
            print(f"Сходство: {similarity:.2f}")
            print(f"Содержание:\n{content}\n")
else:
    print("Аномалий не обнаружено.")
