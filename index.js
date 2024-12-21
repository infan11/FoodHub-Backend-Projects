const express = require('express');
const cors = require('cors');
const app = express();
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = process.env.PORT || 5000;
const jwt = require("jsonwebtoken")
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

        const usersCollection = client.db("FOODHUB").collection("users");
        const ownerUsersCollection = client.db("FOODHUB").collection("ownerUsers");
        // token create
        app.post("/jwt", async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.JWT_WEB_TOKEN, { expiresIn: "1hr" })
            res.send({ token })
        });
        const verifyToken = (req, res, next) => {
            console.log("inside verify token ", req.headers.authorization);
            if (!req.headers.authorization) {
                return res.status(401).send({ message: "Unauthorized access" })
            }
            const token = req.headers.authorization.split(" ")[1];
            jwt.verify(token, process.env.JWT_WEB_TOKEN, (err, decoded) => {
                if (err) {
                    return res.status(403).send({ message: "forbiidden access" })
                }
                req.decoded = decoded;
                next();
            })
        }
        // verify admin 
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const isAdmin = user?.role === "admin";
            if (!isAdmin) {
                return res.status(403).send({ message: "forbidden access" })
            }
            next();
        }
        const verifyModerator = async (req, res , next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const isModerator = user?.role === "moderator";
            if (!isModerator) {
                return res.status(403).send({ message: "forbidden access" })
            }
            next();
        }
        app.get("/users/admin/:email", verifyToken, verifyAdmin, async (req, res) => {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: "forbidden access" });
            }
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const admin = user?.role === "admin"; // Simplified
            res.send({ admin });
        });
        
        app.get("/users/moderator/:email", verifyToken, async (req, res) => {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: "forbidden access" });
            }
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const moderator = user?.role === "moderator"; // Simplified
            res.send({ moderator });
        });
        
        app.get("/users", verifyToken,verifyAdmin, verifyModerator, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result)
        })
        app.post("/users", async (req, res) => {
            const user = req.body;
            const result = await usersCollection.insertOne(user);
            res.send(result)
        })
        app.delete("/users/:id", verifyToken,verifyAdmin, verifyModerator ,async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await usersCollection.deleteOne(query);
            console.log(result);
            res.send(result)
        })

        // user verify admin 
        app.patch("/users/admin/:id", verifyToken,verifyAdmin, async (req, res) => {
            const id = req.params.id;
            console.log(id);
            const filter = { _id: new ObjectId(id) }
            console.log(filter);
            const updateDoc = {
                $set: {
                    role: "admin"
                }
            }
            const result = await usersCollection.updateOne(filter, updateDoc)
            console.log(result);
            res.send(result)
        })

        app.patch("/users/moderator/:id",verifyToken ,verifyAdmin , async (req, res) => {
            const id = req.params.id;
            console.log(id);
            const filter = { _id: new ObjectId(id) }
            console.log(filter);
            const updateDoc = {
                $set: {
                    role: "moderator"
                }
            }
            const result = await usersCollection.updateOne(filter, updateDoc)
            console.log(result);
            res.send(result)
        })
        // ownerUsers
        app.get("/ownerUsers", async (req, res) => {
            const result = await ownerUsersCollection.find().toArray();
            res.send(result)
        })
        app.post("/ownerUsers", async (req, res) => {
            const ownerUser = req.body;
            const result = await ownerUsersCollection.insertOne(ownerUser);
            res.send(result)
        })
        app.delete("/ownerUsers/:id", async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await ownerUsersCollection.deleteOne(query);
            console.log(result);
            res.send(result)
        })
        app.patch("/ownerUsers/restaurantOwner/:id", async (req, res) => {
            const id = req.params.id;
            console.log(id);
            const filter = { _id: new ObjectId(id) }
            console.log(filter);
            const updateDoc = {
                $set: {
                    position: "restaurantOwner"
                }
            }
            const result = await ownerUsersCollection.updateOne(filter, updateDoc)
            console.log(result);
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
app.listen(port, () => {
    console.log(`Signnel crud server ${port}`);
})