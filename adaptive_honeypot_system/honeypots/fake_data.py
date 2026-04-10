import uuid
USERS = [{"id":1,"username":"admin","bio":"Editor-in-chief at Meridian."},{"id":2,"username":"alice","bio":"Software engineer."}]
ARTICLES = [
    {"id":1,"title":"Understanding TCP Congestion Control","summary":"A practical walkthrough of how TCP manages network congestion.","category":"Infrastructure","tags":["tcp","networking"],"read_time":8,"author":USERS[0],"created_at":"2024-11-01T08:00:00"},
    {"id":2,"title":"PostgreSQL Index Types: When to Use What","summary":"B-tree, Hash, GIN, BRIN — each index type solves a different class of query.","category":"Performance","tags":["postgres","database"],"read_time":6,"author":USERS[1],"created_at":"2024-11-10T10:30:00"},
    {"id":3,"title":"Container Networking from First Principles","summary":"How Docker's bridge networking actually works.","category":"Infrastructure","tags":["docker","networking"],"read_time":10,"author":USERS[0],"created_at":"2024-11-18T14:00:00"},
    {"id":4,"title":"Designing for Observability","summary":"Logs are your primary debugging interface in production.","category":"Architecture","tags":["observability","logging"],"read_time":7,"author":USERS[1],"created_at":"2024-12-02T09:00:00"},
]
def make_token(): return f"eyJhbGciOiJIUzI1NiJ9.{uuid.uuid4().hex}.fake"
