const express = require('express');
const cors = require('cors');
const app = express();
const bodyParser = require('body-parser');
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = process.env.PORT || 5000;
const stripe = require("stripe")(process.env.VITE_STRIPE_SECRET_KEY);
const jwt = require("jsonwebtoken");
const { default: axios } = require('axios');
// MIDDLEWERE
app.use(express.json())
app.use(cors());
app.use(express.urlencoded());


const uri = `mongodb+srv://${process.env.DBNAME}:${process.env.DBPASS}@cluster0.lopynog.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;


const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {


        const usersCollection = client.db("FOODHUB").collection("users");
        const restaurantUploadCollection = client.db("FOODHUB").collection("restaurantUpload");
        // const foodsCollection = client.db("FOODHUB").collection("foods");
        const addFoodCollection = client.db("FOODHUB").collection("addFood");
        const paymentCollection = client.db("FOODHUB").collection("payment");
        const districtCollection = client.db("FOODHUB").collection("districtAvailable");
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

        app.get("/users/moderator/:email", verifyToken, verifyModerator, async (req, res) => {
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

        app.get("/users", verifyToken, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result)
        })
        app.get('/users/check-name', async (req, res) => {
            try {
                const { name } = req.query;
                if (!name) {
                    return res.status(400).json({ error: "Name parameter is required." });
                }

                const existingUser = await usersCollection.findOne({ name: name.trim() });

                res.json({ exists: !!existingUser });
            } catch (error) {
                console.error("Error checking name:", error);
                res.status(500).json({ error: "Internal server error." });
            }
        });
        // app.post("/users" , async (req, res) => {
        //     const userInfo = req.body;
        //     const result = await usersCollection.insertOne(userInfo);
        //     console.log(result);
        //     res.send(result)
        // })
        app.put("/users", async (req, res) => {
            const user = req.body;
            const query = { email: user?.email };
            const isExists = await usersCollection.findOne(query);

            const options = { upsert: true };
            const updateDoc = {
                $set: {
                    ...user,
                    isNew: user.restaurantAdddress && user.restaurantNumber ? true : false,
                    timestemp: Date.now(),
                }
            };

            const result = await usersCollection.updateOne(query, updateDoc, options);
            res.send(result);
        });

        app.delete("/users/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await usersCollection.deleteOne(query);
            console.log(result);
            res.send(result)
        })
        const verifyRole = (role) => {
            return async (req, res, next) => {
                const email = req.decoded.email;
                const user = await usersCollection.findOne({ email });
                if (!user || user.role !== role) {
                    return res.status(403).send({ message: "forbidden access" });
                }
                next();
            };
        };
        // user verify admin 
        app.patch("/users/admin/:id", verifyToken, verifyRole("admin"), async (req, res) => {
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
            const query = { email };
            const user = await usersCollection.findOne(query);
            const isOwner = user?.role === "owner";
            if (!isOwner) {
                return res.status(403).send({ message: "forbidden access" });
            }
            next();
        };
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

        app.patch("/users/restaurantOwner/:id", verifyToken,  async (req, res) => {
            const id = req.params.id;
            console.log("owner id", id);
            const filter = { _id: new ObjectId(id) }
            console.log("owner ", filter);
            const updateDoc = {
                $set: {
                    role: "owner"
                }
            }
            const result = await usersCollection.updateOne(filter, updateDoc)
            console.log("owner result", result);
            res.send(result)
        })


        /// Restaurant info 
        app.get("/restaurantUpload", async (req, res) => {
            const result = await restaurantUploadCollection.find().toArray();
            res.send(result)
        })


        app.post("/restaurantUpload", verifyToken, async (req, res) => {
            const addFood = req.body;
            const result = await restaurantUploadCollection.insertOne(addFood);
            console.log(result);
            res.send(result);
        })

        app.get("/restaurantUpload/:restaurantName", async (req, res) => {
            const restaurantName = req.params.restaurantName;
            const query = { restaurantName: restaurantName };
            const result = await restaurantUploadCollection.findOne(query);
            res.send(result)
        })
        app.get("/restaurantUpload/:districtName", async (req, res) => {
            const districtName = req.params.districtName;
            const query = { districtName: districtName };
            const result = await restaurantUploadCollection.find(query).toArray();
            console.log(result);
            res.send(result);
        })
        app.get("/restaurantUpload/:restaurantName", async (req, res) => {
            const restaurantName = req.params.restaurantName;
            const query = { restaurantName: restaurantName };
            const result = await restaurantUploadCollection.findOne(query);
            res.send(result);
        });

        app.get("/restaurantUpload/district/:districtName", async (req, res) => {
            const districtName = req.params.districtName;
            const query = { districtName: districtName };
            const result = await restaurantUploadCollection.find(query).toArray();
            console.log(result);
            res.send(result);
        });

        app.delete("/restaurantUpload/:restaurantName", async (req, res) => {
            const restaurantName = req.params.restaurantName;
            const query = { restaurantName: restaurantName }
            const result = await restaurantUploadCollection.deleteOne(query);
            res.send(result);
        })
        app.delete("/restaurantUpload/:restaurantName/:foodName", async (req, res) => {
            const { restaurantName, foodName } = req.params;

            const filter = { restaurantName: restaurantName };
            const update = { $pull: { foods: { foodName: foodName } } }; // Remove only the matching food

            const result = await restaurantUploadCollection.updateOne(filter, update);

            if (result.modifiedCount > 0) {
                res.send({ success: true, message: "Food item deleted successfully" });
            } else {
                res.status(404).send({ success: false, message: "Food not found" });
            }
        });
        app.patch("/restaurantUpload/:restaurantName", async (req, res) => {
            const restaurantName = req.params.restaurantName;
            const foodInfo = req.body;
            const query = { restaurantName };
            const updateDoc = {
                $push: { foods: foodInfo }, // Push foodInfo into the "foods" array
            };

            const result = await restaurantUploadCollection.updateOne(query, updateDoc);
            res.send(result);
        });

app.put("/restaurantUpload/:restaurantName/:foodName", async (req, res) => {
    try {
        const { restaurantName, foodName } = req.params;
        const updatedFoodData = req.body;
    
        // Find the restaurant by restaurantName
        const restaurant = await restaurantUploadCollection.findOne({ restaurantName });
    
        if (!restaurant) {
          return res.status(404).json({
            success: false,
            message: "Restaurant not found"
          });
        }
    
        // Find the index of the food item to update
        const foodIndex = restaurant.foods.findIndex(food => food.foodName === foodName);
        
        if (foodIndex === -1) {
          return res.status(404).json({
            success: false,
            message: "Food item not found in this restaurant"
          });
        }
    
        // Create the updated food object
        const updatedFood = {
          ...restaurant.foods[foodIndex],
          ...updatedFoodData
        };
    
        // Update the specific food item in the array
        restaurant.foods[foodIndex] = updatedFood;
    
        // Save the updated restaurant document
        const result = await restaurantUploadCollection.updateOne(
          { restaurantName },
          { $set: { foods: restaurant.foods } }
        );
    
        if (result.modifiedCount > 0) {
          res.json({
            success: true,
            message: "Food item updated successfully",
            updatedFood
          });
        } else {
          res.status(400).json({
            success: false,
            message: "No changes were made to the food item"
          });
        }
      } catch (error) {
        console.error("Error updating food item:", error);
        res.status(500).json({
          success: false,
          message: "Internal server error",
          error: error.message
        });
      }
    });
  
  


        // Foods Related  api 
        app.get("/foods", verifyToken, verifyAdmin, verifyModerator, verifyOwner, async (req, res) => {
            const result = await foodsCollection.find().toArray();
            res.send(result)
        })

        app.delete("/foods/:id", async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await foodsCollection.deleteOne(query);
            res.send(result)
        })

        // SSL Commerce Payment Intent
        app.post("/create-ssl-payment", verifyToken, async (req, res) => {

            const payment = req.body;
            console.log("Received Payment Data:", payment);

            const trxid = new ObjectId().toString();
            payment.transactionId = trxid;
            const initiatePayment = {
                store_id: process.env.SSL_COMMERCE_SECRET_ID,
                store_passwd: process.env.SSL_COMMERCE_SECRET_PASS,
                total_amount: parseFloat(payment.foodPrice),
                currency: "BDT",
                tran_id: trxid,
                success_url: "https://foodhub-d3e1e.web.app/dashboard/paymentHistory",
                fail_url: "http://localhost:5173/dashboard/fail",
                cancel_url: "http://localhost:5173/dashboard/cancel",
                ipn_url: "http://localhost:5173/dashboard/ipn-success-payment",
                shipping_method: "Courier",
                product_name: payment.foodName || "Unknown",
                product_category: payment.category || "General",
                product_profile: "general",
                cus_name: payment.customerName || "Customer",
                cus_email: payment.email || "customer@example.com",
                cus_add1: payment.address || "Unknown Address",
                cus_city: payment.district || "Unknown City",
                cus_country: "Bangladesh",
                cus_phone: payment.contactNumber || "01700000000",
                ship_name: payment.customerName || "Customer",
                ship_add1: payment.address || "Unknown Address",
                ship_city: payment.district || "Unknown City",
                ship_country: "Bangladesh",
                ship_postcode: '4700'
            };

            // console.log("Sending Payment Request:", initiatePayment);

            const inResponse = await axios.post(
                "https://sandbox.sslcommerz.com/gwprocess/v4/api.php",
                new URLSearchParams(initiatePayment).toString(), // Ensure correct encoding
                {
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                }
            );
            const saveData = await paymentCollection.insertOne(payment)
            const gatewayPageURL = inResponse?.data?.GatewayPageURL;
            res.send({ gatewayPageURL })


            // console.log(gatewayPageURL); 
        });
        app.get("/success-payment", async (req, res) => {
            try {
                const { val_id, tran_id } = req.query;
                if (!val_id) {
                    return res.status(400).send("val_id missing");
                }

                const validationURL = `https://sandbox.sslcommerz.com/validator/api/validationserverAPI.php?val_id=${val_id}&store_id=foodh67aed7546ec54&store_passwd=foodh67aed7546ec54@ssl&format=json`;

                const { data } = await axios.get(validationURL);
                //   console.log("SSLCommerz Validation Response:", data);

                if (data.status !== "VALID" && data.status !== "VALIDATED") {
                    // return res.status(400).send({ message: "Invalid Payment" });
                }

                const payment = await paymentCollection.findOne({ transactionId: tran_id });
                //   if (!payment) return res.status(404).send({ message: "Transaction ID not found" });

                const update = await paymentCollection.updateOne(
                    { transactionId: tran_id },
                    { $set: { status: "success" } }
                );

                if (update.modifiedCount > 0) {
                    console.log(" Payment updated successfully");

                    // Optionally delete cart
                    const deletedResult = await addFoodCollection.deleteMany(query);

                    return res.send({ deletedResult });

                } else {
                    return res.status(500).send({ message: "Failed to update payment" });
                }
            } catch (err) {
                console.error(" Error in success-payment:", err);
                res.status(500).send({ message: "Server Error" });
            }
            return res.redirect("https://foodhub-d3e1e.web.app/dashboard/paymentHistory");
        });

        // Import express and MongoDB client before this snippet
        // Assume 'client' is your connected MongoDB client

        app.get('/payments', verifyToken, async (req, res) => {
            try {
                const email = req.query.email;
                if (!email) {
                    return res.status(400).json({ error: "Email query parameter is required" });
                }
                const payments = await paymentCollection
                    .find({ email })
                    .sort({ date: -1 })
                    .toArray();

                res.json(payments);
            } catch (err) {
                console.error("Error fetching payments:", err);
                res.status(500).json({ error: "Internal server error" });
            }
        });

        app.post('/create-payment-intent', async (req, res) => {
            try {
                const { price } = req.body;
                if (!price) {
                    return res.status(400).json({ error: "Price is required" });
                }
                const amount = parseInt(price * 100); // Convert to cents
                console.log("Creating PaymentIntent with amount:", amount);

                const paymentIntent = await stripe.paymentIntents.create({
                    amount: amount,
                    currency: "usd",
                    payment_method_types: ['card'],
                });

                console.log("Client Secret Sent:", paymentIntent.client_secret);
                res.json({ clientSecret: paymentIntent.client_secret });

            } catch (error) {
                console.error("Payment Intent Error:", error);
                res.status(500).json({ error: error.message });
            }
        });

        app.get("/payments/:email", async (req, res) => {
            const query = { email: req.params.email }
            // if (req.params.email !== req.decoded.email) {
            //   return res.status(403).send({ message: "forbidden access" })
            // }
            const result = await paymentCollection.find(query).toArray()
            res.send(result)
        })
        app.post("/payments", async (req, res) => {
            const payment = req.body;
            const paymentResult = await paymentCollection.insertOne(payment);
            
            const query = {
                _id: {
                    $in: payment.items.map(item => new ObjectId(item.foodId))
                }
            };
            
            const deletedResult = await addFoodCollection.deleteMany(query);
            res.send({ paymentResult, deletedResult });
        });

        app.delete("/payments/:id", async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await paymentCollection.deleteOne(query)
            res.send(result)
        })

        // addfood cart api 
        app.get("/addFood", async (req, res) => {
            const email = req.query.email;
            const query = { email: email };
            const result = await addFoodCollection.find(query).toArray()
            res.send(result);
        })
        app.post("/addFood", verifyToken, async (req, res) => {
            try {
              const foodInfo = req.body;
              
             
              if (!foodInfo.foodName || !foodInfo.restaurantName || !foodInfo.email) {
                return res.status(400).json({ error: "Missing required fields" });
              }
      
           
              foodInfo.createdAt = new Date();
              
              const result = await addFoodCollection.insertOne(foodInfo);
              
              if (result.insertedId) {
                return res.status(201).json({
                  success: true,
                  insertedId: result.insertedId,
                  message: "Food item added successfully"
                });
              } else {
                return res.status(500).json({ error: "Failed to add food item" });
              }
            } catch (error) {
              console.error("Error adding food:", error);
              return res.status(500).json({ error: "Internal server error" });
            }
          });
          app.get("/addItem", verifyToken, async (req, res) => {
            try {
              const { email } = req.query;
              const items = await addFoodCollection.find({ email }).toArray();
              res.status(200).json(items);
            } catch (error) {
              res.status(500).json({ error: "Failed to fetch cart items" });
            }
          });
        app.patch("/addFood/:id", async (req, res) => {
            const id = req.params.id;
            const { quantity } = req.body; // Extract updated quantity

            try {
                const query = { _id: new ObjectId(id) };
                const updateDoc = {
                    $set: { quantity: parseInt(quantity) }, // Update the quantity field
                };

                const result = await addFoodCollection.updateOne(query, updateDoc);
                res.send(result);
            } catch (error) {
                res.status(500).send({ error: "Failed to update quantity" });
            }
        });


        app.delete("/addFood/:id", verifyToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await addFoodCollection.deleteOne(query);
            console.log(result);
            res.send(result)
        })

        // DistrictAvailable api
        app.get("/districtAvailable", async (req, res) => {
            const result = await districtCollection.find().toArray();
            res.send(result);
        })

        app.post("/districtAvailable", verifyToken, verifyAdmin, async (req, res) => {
            const district = req.body;
            const result = await districtCollection.insertOne(district)
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