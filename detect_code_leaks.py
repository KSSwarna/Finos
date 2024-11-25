import os
import re
import openai

# Securely load the OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")

if not openai.api_key:
    raise EnvironmentError("OpenAI API key not found. Please set it as an environment variable.")

def analyze_with_spotbugs(java_project_path, spotbugs_path="spotbugs/bin/spotbugs"):
    """
    Runs SpotBugs on a compiled Java project and returns the findings.
    :param java_project_path: Path to the compiled Java project (.class or .jar files)
    :param spotbugs_path: Path to the SpotBugs executable
    :return: SpotBugs output as a string
    """
    try:
        # Construct the SpotBugs command
        command = [spotbugs_path, "-textui", java_project_path]

        # Execute the command and capture output
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(f"SpotBugs error: {result.stderr}")

        return result.stdout
    except Exception as e:
        return f"Error running SpotBugs: {str(e)}"

def analyze_diff_with_llm(diff):
    """
    Analyzes a GitHub diff using OpenAI GPT-4 to detect code anomalies and leaks.
    """
    prompt = f"""
    Analyze the following GitHub diff for security risks, sensitive patterns, improper practices,
    and other anomalies. Provide detailed findings and recommendations:
    ```diff
    {diff}
    ```
    """
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a code security expert."},
                {"role": "user", "content": prompt}
            ]
        )
        return response['choices'][0]['message']['content']
    except Exception as e:
        return f"Error during LLM analysis: {str(e)}"

def scan_for_secrets(diff):
    """
    Scans the diff for sensitive patterns such as API keys, passwords, or secrets.
    """
    secret_patterns = [
        r'aws_access_key_id.*[\'"][A-Z0-9]{16,}[\'"]',  # AWS Access Key
        r'aws_secret_access_key.*[\'"][A-Za-z0-9/+=]{40,}[\'"]',
        r'API[_-]?KEY.*=.*[\'"].*[\'"]',  # Common API keys
        r'DB_PASSWORD.*=.*[\'"].*[\'"]',  # Database passwords
        r'password.*=.*[\'"].*[\'"]',  # General passwords
    ]
    findings = []
    for pattern in secret_patterns:
        matches = re.findall(pattern, diff, re.IGNORECASE)
        if matches:
            findings.extend(matches)
    return findings

def analyze_dependencies(diff, language):
    """
    Analyzes dependencies in the diff for security risks or outdated packages.
    """
    dependencies = []
    if language == "javascript":
        dependencies = re.findall(r'"([^"]+)":\s*"([^"]+)"', diff)  # package.json style
    elif language == "python":
        dependencies = re.findall(r'([a-zA-Z0-9\-_]+)==([\d\.]+)', diff)  # requirements.txt style
    elif language == "java":
        dependencies = re.findall(r'<dependency>(.*?)</dependency>', diff, re.DOTALL)
    return dependencies

def analyze_media_usage(diff):
    """
    Detects media assets (e.g., images, videos) in the diff.
    """
    media_patterns = [r'\.(png|jpg|jpeg|gif|mp4|avi|mov|svg|webp|bmp)\b']
    findings = []
    for pattern in media_patterns:
        matches = re.findall(pattern, diff, re.IGNORECASE)
        if matches:
            findings.extend(matches)
    return findings

def analyze_cryptography(diff):
    """
    Detects the use of insecure cryptographic algorithms or practices in the diff.
    """
    crypto_patterns = [
        r'Cipher\.getInstance\(".*?(DES|ECB).*?"\)',  # Java insecure cipher
        r'hashlib\.md5\(',  # Python MD5 hash
        r'Crypto\.createCipher\(".*?(aes-128-ecb).*?"\)',  # Node.js insecure cipher
    ]
    findings = []
    for pattern in crypto_patterns:
        matches = re.findall(pattern, diff, re.IGNORECASE)
        if matches:
            findings.extend(matches)
    return findings

def analyze_ai_ml_usage(diff):
    """
    Detects the usage of AI/ML-related libraries in the diff.
    """
    ml_patterns = [
        r'import (tensorflow|torch|sklearn|keras|pandas|numpy)',  # Python AI/ML libraries
        r'require\("(tensorflow|ml5)"\)',  # Node.js AI/ML libraries
    ]
    findings = []
    for pattern in ml_patterns:
        matches = re.findall(pattern, diff, re.IGNORECASE)
        if matches:
            findings.extend(matches)
    return findings

def detect_exfiltration(diff):
    """
    Detects patterns that suggest exfiltration of data, e.g., using media formats.
    """
    exfiltration_patterns = [
        r'base64\.b64encode',  # Python Base64 encoding
        r'Buffer\.toString\("base64"\)',  # Node.js Base64 encoding
        r'.*\.write\(.*file.*(png|jpg|jpeg|gif|mp4)\)',  # Writing media files
    ]
    findings = []
    for pattern in exfiltration_patterns:
        matches = re.findall(pattern, diff, re.IGNORECASE)
        if matches:
            findings.extend(matches)
    return findings

def detect_language_from_diff(diff):
    """
    Detects the programming language based on file extensions in the diff.
    """
    if re.search(r'\.java\b', diff):
        return "java"
    elif re.search(r'\.py\b', diff):
        return "python"
    elif re.search(r'\.js\b', diff):
        return "javascript"
    elif re.search(r'\.go\b', diff):
        return "go"
    elif re.search(r'\.cs\b', diff):
        return "csharp"
    else:
        return "unknown"

def main():
    # Example GitHub diff (replace with actual diff from GitHub API or file)
    diff = """
    diff --git a/src/main/java/Example.java b/src/main/java/Example.java
    index abc123..def456 100644
    --- a/src/main/java/Example.java
    +++ b/src/main/java/Example.java
    @@ -10,7 +10,7 @@ public class Example {
         private String apiKey = "HARDCODED_API_KEY"; // Example sensitive data
         public void process() {
    -        System.out.println("Old Code");
    +        System.out.println("Updated Code");
             // Added new sensitive information handling
             String password = "plaintext_password"; // Example risky pattern
         }
    }
    """
	
     # Paths
    java_project_path = "./out"  # Path to compiled Java project
    spotbugs_path = "./spotbugs/bin/spotbugs"  # Path to SpotBugs installation


    # Detect language
    language = detect_language_from_diff(diff)

    # Perform analysis
    llm_analysis = analyze_diff_with_llm(diff)
    secrets = scan_for_secrets(diff)
    dependencies = analyze_dependencies(diff, language)
    media_files = analyze_media_usage(diff)
    cryptography_issues = analyze_cryptography(diff)
    ai_ml_findings = analyze_ai_ml_usage(diff)
    exfiltration_findings = detect_exfiltration(diff)
    # Perform SpotBugs Analysis for Java
    spotbugs_findings = ""
    if language == "java":
        spotbugs_findings = analyze_with_spotbugs(java_project_path, spotbugs_path)


    # Write results to a file
    with open("analysis_results.txt", "w") as file:
        file.write("Detected Language: " + language + "\n\n")
        file.write("LLM Analysis:\n" + llm_analysis + "\n\n")
        file.write("Secrets Found:\n" + str(secrets) + "\n\n")
        file.write("Dependencies Found:\n" + str(dependencies) + "\n\n")
        file.write("Media Files Found:\n" + str(media_files) + "\n\n")
        file.write("Cryptography Issues:\n" + str(cryptography_issues) + "\n\n")
        file.write("AI/ML Usage:\n" + str(ai_ml_findings) + "\n\n")
        file.write("Exfiltration Patterns:\n" + str(exfiltration_findings) + "\n\n")

if __name__ == "__main__":
    main()
