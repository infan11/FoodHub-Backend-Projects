const express = require('express');
const cors = require('cors');
const app = express();

require("dotenv").config();
const { MongoClient, ServerApiVersion } = require('mongodb');
const port = process.env.PORT || 5000;

// MIDDLEWERE
app.use(express.json())
app.use(cors());

const uri = `mongodb+srv://${process.env.DBNAME}:${process.env.DBPASS}@cluster0.lopynog.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)

        const usersCollection = client.db("FOODHUB").collection("users")
        app.get("/users", async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result)
        })
        app.post("/users", async (req, res) => {
            const user = req.body;
            const result = await usersCollection.insertOne(user);
            res.send(result)
        })
        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error

    }
}
run().catch(console.dir);

app.get("/", (req, res) => {
    res.send("FOODHUB server is running")
})
app.listen( port,() => {
    console.log(`Signnel crud server ${port}`);
})