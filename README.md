# 🛡️ ThreatLens AI

ThreatLens AI is an AI-powered malware detection and analysis platform that uses **Machine Learning** and **static analysis** to identify potentially malicious executable files. Users can upload suspicious files, perform analysis, generate prediction results, and store reports in a **PostgreSQL** database for future reference.

This project is being developed as an academic cybersecurity project to demonstrate how Artificial Intelligence can enhance malware detection and threat analysis.

---

**✨ Features**

* 📁 Secure file upload
* 🔍 Static malware analysis
* 🤖 Machine Learning-based malware classification
* 📊 Risk score generation
* 🗄️ PostgreSQL database integration
* 📋 Analysis reports and history
* 🚨 Threat alert generation
* 📈 Modular and scalable architecture

---

**🛠️ Tech Stack**

| Category                | Technologies                      |
| ----------------------- | --------------------------------- |
| **Frontend**            | React.js, HTML5, CSS3, JavaScript |
| **Backend**             | Python, Flask                     |
| **Machine Learning**    | Scikit-learn, Pandas, NumPy       |
| **Database**            | PostgreSQL                        |
| **Database Management** | pgAdmin 4                         |
| **Version Control**     | Git, GitHub                       |
| **Development Tools**   | VS Code, Postman                  |

---

**📂 Project Structure**

```text
ThreatLens-AI/
│
├── frontend/                  
│   ├── assets/
│   ├── components/
│   ├── pages/
│   ├── services/
│   ├── styles/
│   └── main.jsx
│
├── backend/                   
│   ├── routes/
│   ├── controllers/
│   ├── models/
│   ├── middleware/
│   ├── services/
│   ├── authentication/
│   ├── file_analysis/
│   ├── ai_model/
│   ├── config/
│   ├── utils/
│   ├── reports/
│   ├── uploads/
│   └── main.py
│
├── database/                  
│   ├── schema.sql
│   ├── seed.sql
│   └── migrations/
│
├── documentation/
├── tests/
├── docker/
├── scripts/
├── README.md
├── .gitignore
├── package.json
└── requirements.txt
```

---

**📋 Prerequisites**

* Python 3.10+
* Node.js & npm
* PostgreSQL
* pgAdmin 4
* Git
* Visual Studio Code

---

**🚀 Getting Started**

Clone the repository:

```bash
git clone https://github.com/your-username/ThreatLens-AI.git
cd ThreatLens-AI
```

Install backend dependencies:

```bash
pip install -r requirements.txt
```

Install frontend dependencies:

```bash
npm install
```

Configure the database:

* Create a PostgreSQL database named **`threatlens_db`**.
* Execute the SQL scripts inside the `database/` folder.

Run the application:

```bash
python main.py
```

```bash
npm start
```

---

**🎯 Project Roadmap**

* Dynamic malware analysis
* VirusTotal API integration
* JWT authentication
* Real-time threat monitoring
* PDF report generation
* Interactive analytics dashboard
* Docker deployment

---

**📄 License**

This project is developed for educational and research purposes.
