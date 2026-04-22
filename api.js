const express = require('express');
const cors    = require('cors');
const MongoClient = require('mongodb').MongoClient;
const ObjectID = require('mongodb').ObjectId;
const dotenv = require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt    = require('jsonwebtoken');

const MongoUrl = process.env.MONGO_URL;
const client = new MongoClient(MongoUrl);

const app = express();

// Constants imported from .env
const port = Number(process.env.PORT) || 3000;
const saltRounds = Number(process.env.SALT_ROUNDS) || 10;
const jwtSecret = String(process.env.JWT_SECRET) || "some default string that you should overwrite with the JWT_SECRET env variable";

app.use(express.json());
app.use(cors());

//TODO
//app.use(checkApiKeys());

/******
 * async function checkApiKeys(req,res,next){
 *
 * ...
 *
 * }
 ******/

function authenticate(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expects "Bearer <token>"

    if (!token) return res.status(401).send('Missing token');

    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).send('Invalid or expired token');
    }
}

app.post('/register', async (req,res) => {
	const emailRegex = /^[\w\-\.]+(\+[\w\-\.]+)?@([\w-]+\.)+[\w-]{2,}$/;
	let missingFields = 0;
	// Ogni check fallito imposta un bit su 1, poi il client puo' controllare i bit flippati per capire cosa manca
	// Each failed check flips a bit to 1, then the client can check what bits are flipped to see what's missing
	if(req.body.email == null){ console.log('Missing field: email'); missingFields += 1 }       // 0000000000001
	else if(!emailRegex.test(req.body.email)){
		console.log('Invalid field: email'); missingFields += 1
	}
	if(req.body.password == null){ console.log('Missing field: password'); missingFields += 2 } // 0000000000010
  if(req.body.phone == null){ console.log('Missing field: phone'); missingFields =+ 4096 } // 1000000000000
	if(req.body.restaurateur == null){ console.log('Missing check: restaurateur'); missingFields += 4 }         // 0000000000100
	else{
		if(req.body.restaurateur == true){
			if(req.body.iva == null){ console.log('Missing field: iva'); missingFields += 8 }   // 0000000001000
			if(req.body.bankAccount == null){ console.log('Missing fields: bankAccount.*') ; missingFields += 48 } // 0000000110000
			else{
				if(req.body.bankAccount.iban == null){ console.log('Missing field: bankAccount.iban'); missingFields += 16 } // 0000000010000
				if(req.body.bankAccount.bankName == null){ console.log('Missing field: bankAccont.bankName'); missingFields += 32 } // 0000000100000
			}
		}
	}
	if(req.body.address == null){ console.log('Missing fields: address.*') ; missingFields += 448 }              // 0000111000000
	else {
		if(req.body.address.street == null){ console.log('Missing field: address.street'); missingFields += 64 } // 0000001000000
		if(req.body.address.city == null){ console.log('Missing field: address.city'); missingFields += 128 }    // 0000010000000
		if(req.body.address.zip == null){ console.log('Missing field: address.zip'); missingFields += 256 }      // 0000100000000
	}
	if(req.body.paymentCard == null){ console.log('Missing fields: paymentCard.*'); missingFields += 3584 }      // 0111000000000
	else{
		if(req.body.paymentCard.number == null){ console.log('Missing field: paymentCard.number'); missingFields += 512 }    // 0001000000000
		if(req.body.paymentCard.expDate == null){ console.log('Missing field: paymentCard.expDate'); missingFields += 1024 } // 0010000000000
		if(req.body.paymentCard.cvv == null){ console.log('Missing field: paymentCard.cvv'); missingFields += 2048 }         // 0100000000000
	}
	if(missingFields !== 0){ return res.status(400).send(missingFields); }

	try {
		// Connecting to db
		await client.connect();
		const db = client.db("foodel");
		const users = db.collection("users");
		console.log('db connected');

		// Dupes check
		const existingUser = await users.findOne({email: req.body.email});
		if (existingUser){
			console.log(`existingUser: ${existingUser.email}`)
			return res.status(409).send('Email already in use');
		}

		// Password hashing and user creation
		let newUser = {};

		const salt = await bcrypt.genSalt(saltRounds);
		const hashedPassword = await bcrypt.hash(req.body.password, salt);
		// console.log(`hashed pw: ${hashedPassword}`)

		// User creation
		if(req.body.restaurateur === true){
			console.log('New restaureateur')
			newUser = {

				email: req.body.email,
				password: hashedPassword,
        phone: req.body.phone,
				restaurateur: req.body.restaurateur,
				iva: req.body.iva,
				bankAccount: req.body.bankAccount,
				address: req.body.address,
				paymentCard: req.body.paymentCard
			};
		} else {
			console.log('New commoner')
			newUser = {
				email: req.body.email,
				password: hashedPassword,
        phone: req.body.phone,
				restaurateur: req.body.restaurateur,
				address: req.body.address,
				paymentCard: req.body.paymentCard
			};
		}

		// console.log(`newUser.password: ${newUser.password}`);

		// Insert into db
		await users.insertOne(newUser);

		// Fetching user from database to get the autogenerated field _id
		// Cercando l'utente dal database per ottenereil campo autogenerato _id
		const email = req.body.email
		newUser = await users.findOne({ email });

		// JWT
		const payload = {
			email: newUser.email,
			sub: newUser._id,
			restaurateur: newUser.restaurateur
		};

		// Signing
		const token = jwt.sign(payload, jwtSecret, {
			expiresIn: '30m'
		});

		console.log('User registered and logged in: ', email);

		await client.close();
		res.status(201).json({ token });
	} catch (err) {
		console.error("Error in /register:", err);
		res.status(500).send("Server error");
	}
});

app.post('/login', async (req,res) => {
	const { email, password } = req.body;

	try{
		// Connection to DB
		await client.connect();
		const db = client.db("foodel");
		const users = db.collection("users");

		// Checking if the user exists
		const user = await users.findOne({ email });
		if (!user) {
			console.log("User not found");
			return res.status(401).send("Invalid credentials");
		}

		// Password check
		const passwordMatch = await bcrypt.compare(password, user.password);
		if(!passwordMatch) {
			console.log("Invalid password");
			return res.status(401).send("Invalid credentials");
		}

		// JWT
		const payload = {
			email: user.email,
			sub: user._id,
			restaurateur: user.restaurateur
		};

		// Signing
		const token = jwt.sign(payload, jwtSecret, {
			expiresIn: '30m'
		});

		console.log('User logged in: ', email);
		res.status(200).json({ token });
	} catch(err){
		console.error("Error in /login: ", err);
		res.status(500).send("Server error");
	}
});

app.get('/users/me', authenticate, async (req,res) => {
  try {
    await client.connect();
    const db = client.db("foodel");
    const users = db.collection("users");

    const user = await users.findOne(
      { _id: new ObjectID(req.user.sub) },
      { projection: { password: 0 } }
    );

    if (!user) return res.status(404).send("You don't exist");

    await client.close;

    console.log(`User ${user.email} got requested`);
    res.status(200).json(user);
  } catch(err) {
    console.error("Error in GET /users/me: ", err);
    res.status(500).send("Server error");
  }
});

app.delete('/users/me', authenticate, async (req,res) => {
  try {
    await client.connect();
    const db = client.db("foodel");
    const users = db.collection("users");

    const user = await users.findOne({ _id: new ObjectID(req.user.sub)});

    if (!user) return res.status(500).send("this is awkward, this should not be possible");

    const result = await users.deleteOne({ _id: user._id });
    await client.close();

    if (result.deletedCount == 1){
      console.log(`Deleted user ${user.email}`);
      return res.status(200).send("you got deleted");
    }
    else {
      console.log("Attempted user deletion failed");
      return res.status(400).send("something went wrong and I don't know what it could be")
    }
  }
  catch(err){
    console.error("Error in DELETE /users/me: ", err);
    res.status(500).send("Server error");
  }
});

app.patch('/users/me', authenticate, async (req,res) => {
  try {
    await client.connect();
    const db = client.db("foodel");
    const users = db.collection("users");

    // questo endpoint serve a modificare solo le informazioni accessorie all'account,
    // per email password e tipo di profilo ci saranno degli endpoint dedicati con
    // verifiche aggiuntive
    if (req.body.password != null ||
        req.body.restaurateur != null ||
        req.body._id != null ||
        req.body.email != null){
      return res.status(403).send("Can't update the specified fields");
    }

    const user = await users.findOne({ _id: new ObjectID(req.user.sub) })

    if (!user) return res.status(500).send("this is awkward, this should not be possible");

    const query = { _id: user._id };
    const update = { $set: req.body };
    const options = { upsert: false };
    await users.updateOne(query, update, options);

    await client.close();
    return res.status(200).send("Update successful");
  } catch(err) {
    console.error("Error in PATCH /users/me:", err);
    res.status(500).send("Server error");
  }
})

app.get('/teapot', async (req,res) => {
	console.log('/teapot test');
	res.status(418).send('This is not a coffee machine');
});

app.listen(port, () => {
  if(process.env.JWT_SECRET == null){
    console.log("WARNING: JWT secret env variable not set, I suggest you to set one");
  }
	console.log(`App listening on port ${port}, visit http://127.0.0.1:${port}`);
});
