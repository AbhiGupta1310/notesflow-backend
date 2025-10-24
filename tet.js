const { MongoClient, ServerApiVersion } = require("mongodb");
const uri =
  "mongodb+srv://abhi:QWERTY@cluster0.iedpbsa.mongodb.net/?appName=Cluster0"; // copy from step 2

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("✅ Connected to MongoDB!");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
  } finally {
    await client.close();
  }
}

run();
