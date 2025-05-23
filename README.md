
# File Metadata Management System

A comprehensive solution for managing file metadata, including extracting and storing information about various file types, running an inference server for additional data processing, and providing a web-based interface for browsing and viewing file details.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

Before setting up the project, ensure you have the following installed:

- Python 3.8 or higher
- Java (for running Apache Tika Server)
- pip (Python package installer)
- Node.js and npm (for React app development, if needed)

### Setup

1. **Clone the repository**:
   ```sh
   git clone https://github.com/carstenbund/meta-server.git
   cd meta-server
   ```

2. **Install Python dependencies**:
   ```sh
   pip install -r requirements.txt
   ```

3. **Download Apache Tika Server**:
   - Download the Tika server JAR from [Apache Tika](https://tika.apache.org/download.html).
   - Place the JAR file in a known directory, e.g., `/path/to/tika-server.jar`.

## Usage

### Running the Tika Server

Start the Tika server, which is used for extracting text from documents:

```sh
java -jar /path/to/tika-server.jar
```

### Setting Up the Inference Server

The inference server uses models from Hugging Face's `transformers` library to infer additional metadata about the files.

1. **Create `inference_server.py`**.

2. **Install necessary packages**:
   ```sh
   pip install flask transformers
   ```

3. **Run the inference server**:
   ```sh
   python inference_server.py
   ```

### Scanning Files

To scan and process files, use the `scan_files.py` script.

1. **Create `scan_files.py`**.

2. **Install necessary packages**:
   ```sh
   pip install requests python-magic langdetect tika pefile
   ```

3. **Run the scan script**:
   ```sh
   python scan_files.py
   ```

### Running the Web Application

To run the web application that allows browsing and viewing file details:

1. **Create `app.py`**.

2. **Install necessary packages**:
   ```sh
   pip install flask sqlalchemy flask-cors requests python-magic langdetect tika pefile
   ```

3. **Create the `index.html` file in the `static` directory**.

4. **Run the Flask application**:
   ```sh
   python app.py
   ```

### Accessing the Web Application

Open your web browser and navigate to `http://localhost:5000` to browse and view file details.



## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a new Pull Request.

## License

This project is licensed under the MIT License.
