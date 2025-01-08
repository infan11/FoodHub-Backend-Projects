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
        // const usersCollection = client.db("FOODHUB").collection("users");
        const foodsCollection = client.db("FOODHUB").collection("foods");
        // token create
        app.post("/jwt", async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.JWT_WEB_TOKEN, { expiresIn: "1hr" })
            res.send({ token })
        });
        const verifyToken = (req, res, next) => {
            // console.log("inside verify token ", req.headers.authorization);
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
        const verifyModerator = async (req, res, next) => {
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
            let admin = false
            if (user) {
                admin = user?.role === "admin"
            }
            res.send({ admin })
        });

        app.get("/users/moderator/:email", verifyToken, async (req, res) => {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: "forbidden access" });
            }
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            if (user?.role === "moderator") {
                return res.send({ moderator: true });
            }
            res.send({ moderator: false });
        });

        app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result)
        })
// app.post("/users" , async (req, res) => {
//     const userInfo = req.body;
//     const result = await usersCollection.insertOne(userInfo);
//     console.log(result);
//     res.send(result)
// })
        app.put("/users", async (req, res) => {
            const user = req.body;
            const query = { email: user?.email }
            const isExists = await usersCollection.findOne(query)
            if (isExists) return res.send(isExists)
            const options = { upsert: true }

            const updateDoc = {
                $set: {
                    ...user,
                    timestemp: Date.now(),
                }

            }
            const result = await usersCollection.updateOne(query, updateDoc, options)
            res.send(result)
        })
        app.delete("/users/:id", verifyToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await usersCollection.deleteOne(query);
            console.log(result);
            res.send(result)
        })

        // user verify admin 
        app.patch("/users/admin/:id", verifyToken, verifyAdmin, async (req, res) => {
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

        app.patch("/users/moderator/:id", verifyToken, verifyAdmin, async (req, res) => {
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

        const verifyOwner = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const isOwner = user?.role === "owner";
            if (isOwner) {
                return res.status(403).send({ message: "forbidden access" })
            }
            next()
        }
        app.get("/users/restaurantOwner/:email", verifyToken, async (req, res) => {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: "forbidden access" });
            }
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            let owner = false;
            if (user) {
                owner = user.role === "owner";
            }
            res.send({ owner });
        });

        app.patch("/users/restaurantOwner/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            console.log("owner id", id);
            const filter = { _id: new ObjectId(id) }
            console.log("owner " , filter);
            const updateDoc = {
                $set : {
                    role : "owner"
                }
            }
            const result = await usersCollection.updateOne(filter , updateDoc)
            console.log("owner result" , result);
            res.send(result)
        })
        // app.put("/users", async (req, res) => {
        //     const ownerUser = req.body;
        //     const query = { email: ownerUser?.email };
        //     const isExists = await usersCollection.findOne(query);
        //     if (isExists) return res.send(isExists)
        //     const options = { upsert: true }
        //     const updateDoc = {
        //         $set: {
        //             ...ownerUser,
        //             timestemp: Date.now()
        //         }
        //     }
        //     const result = await usersCollection.updateOne(query, updateDoc, options)
        //     res.send(result)
        // })
        // app.delete("/users/:id", verifyToken, verifyAdmin, async (req, res) => {
        //     const id = req.params.id;
        //     const query = { _id: new ObjectId(id) }
        //     const result = await usersCollection.deleteOne(query);
        //     console.log(result);
        //     res.send(result)
        // })
        // app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
        //     const result = await usersCollection.find().toArray();
        //     res.send(result)
        // })




        // Foods Related  api 
        app.get("/foods", verifyToken, verifyAdmin, verifyModerator, verifyOwner, async (req, res) => {
            const result = await foodsCollection.find().toArray();
            res.send(result)
        })
        app.post("/foods", async (req, res) => {
            const addFood = req.body;
            const result = await foodsCollection.insertOne(addFood);
            console.log(result);
            res.send(result);
        })
        app.delete("/foods/:id", async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await foodsCollection.deleteOne(query);
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