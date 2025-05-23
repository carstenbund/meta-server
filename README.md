# File Metadata Management System

A comprehensive solution for scanning files, extracting metadata and providing a web interface to browse the results.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites
Ensure the following are installed:

- Docker
- Docker Compose
- Java (for the Apache Tika server)
- Python 3.8+ (optional for running scripts directly)

### Setup
1. Clone the repository:
   ```sh
   git clone https://github.com/carstenbund/meta-server.git
   cd meta-server
   ```
2. Build the container images:
   ```sh
   docker-compose build
   ```

## Usage

### Run the Tika Server
Start the Apache Tika server used for text extraction:
```sh
java -jar /path/to/tika-server.jar
```

### Launch the Services
Use docker-compose to start the scanner, indexer, inference server and web application:
```sh
docker-compose up
```

The web interface will be available at `http://localhost:5000`.

### Development without Docker (optional)
If you prefer running the components manually, install the dependencies from
`requirements.txt` and run the scripts located in the `server`, `scanner`,
`indexer` and `inference_server` directories.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a new Pull Request.

## License

This project is licensed under the MIT License.
