const express = require("express")
const mongoose = require("mongoose")
const dotenv = require("dotenv")
const jwt = require("jsonwebtoken")
const cors = require("cors")
const cookieParser = require("cookie-parser")
const bcrypt = require("bcryptjs")
const ws = require("ws")
const fs = require("fs")

const User = require("./models/User")
const Message = require("./models/Message")

dotenv.config()
mongoose.connect(process.env.MONGO_URL)
const jwtSecret = process.env.JWT_SECRET
const bcryptSalt = bcrypt.genSaltSync(10)

const app = express()

app.use("/uploads", express.static(__dirname + "/uploads"))
app.use(express.json())
app.use(cookieParser())
app.use(cors({
    credentials: true,
    origin: process.env.CLIENT_URL,
}))

async function getUserDataFromRequest(req) {
    return new Promise((resolve, reject) => {
        const token = req.cookies?.token
        if (token) {
            const decoded = jwt.verify(token, jwtSecret)
            resolve(decoded)
        } else {
            reject("no token")
        }
    })
}

app.get("/test", (req, res) => {
    res.json("test ok")
})

app.get("/messages/:userId", async (req, res) => {
    const { userId } = req.params
    const userData = await getUserDataFromRequest(req)
    const ourUserId = userData.userId
    const messages = await Message.find({
        sender: { $in: [userId, ourUserId] },
        recipient: { $in: [userId, ourUserId] },
    }).sort({ createdAt: 1 })
    res.json(messages)
})

app.get("/people", async (req, res) => {
    const users = await User.find({})
    res.json(users)
})

app.get("/profile", (req, res) => {
    const token = req.cookies?.token
    if (!token) {
        return res.status(401).json("no token")
    }
    const decoded = jwt.verify(token, jwtSecret)
    res.json(decoded)
})

app.post("/login", async (req, res) => {
    const { username, password } = req.body
    try {
        const foundUser = await User.findOne({ username })
        if (foundUser) {
            const passOk = bcrypt.compareSync(password, foundUser.password)
            if (passOk) {
                const token = jwt.sign({ userId: foundUser._id, username }, jwtSecret)
                return res.cookie("token", token).json({ id: foundUser._id })
            }
            res.status(401).json({ "message": "username or passowrd incorrect" })
        }
    } catch (err) {
        res.status(500).json({ "message": err })
    }
})

app.post("/logout", (req, res) => {
    res.cookie("token", "").json("ok")
})

app.post("/register", async (req, res) => {
    const { username, password } = req.body
    try {
        const hashedPassword = bcrypt.hashSync(password, bcryptSalt)
        const createdUser = await new User({
            username,
            password: hashedPassword,
        }).save()
        const token = jwt.sign({ userId: createdUser._id, username }, jwtSecret)
        res.cookie("token", token).status(201).json({ id: createdUser._id, username })
    } catch (err) {
        res.status(500).json(err)
    }
})

const server = app.listen(4040)

const wss = new ws.WebSocketServer({ server })
wss.on("connection", (connection, req) => {
    function notifyAboutOnlinePeople() {
        [...wss.clients].forEach(client => {
            client.send(JSON.stringify({
                online: [...wss.clients].map(c => ({ userId: c.userId, username: c.username }))
            }))
        })
    }

    connection.isAlive = true

    connection.timer = setInterval(() => {
        connection.ping()
        connection.deathTimer = setTimeout(() => {
            connection.isAlive = false
            clearInterval(connection.timer)
            connection.terminate()
            notifyAboutOnlinePeople()
        }, 1000);
    }, 5000);

    connection.on("pong", () => {
        clearTimeout(connection.deathTimer)
    })

    const cookies = req.headers.cookie
    if (cookies) {
        const tokenCookieString = cookies.split(";").find(str => str.startsWith("token="))
        if (tokenCookieString) {
            const token = tokenCookieString.split("=")[1]
            if (token) {
                const decoded = jwt.verify(token, jwtSecret)
                const { userId, username } = decoded
                connection.userId = userId
                connection.username = username
            }
        }
    }

    connection.on("message", async (message) => {
        const messageData = JSON.parse(message.toString())
        const { recipient, text, file } = messageData
        let filename = null
        if (file) {
            const parts = file.name.split(".")
            const ext = parts[parts.length - 1]
            filename = Date.now() + "." + ext
            const path = __dirname + "/uploads/" + filename
            const bufferData = new Buffer(file.data.split(",")[1], "base64")
            fs.writeFile(path, bufferData, () => {
                console.log("file saved: " + path)
            })
        }
        if (recipient && (text || file)) {
            const messageDoc = await Message.create({
                sender: connection.userId,
                recipient,
                text,
                file: file ? filename : null,
            });
            [...wss.clients]
                .filter(c => c.userId === recipient)
                .forEach(c => c.send(JSON.stringify({
                    text,
                    sender: connection.userId,
                    _id: messageDoc._id,
                    recipient,
                    file: file ? filename : null,
                })))
        }
    });
    notifyAboutOnlinePeople()
})

wss.on("close", data => {
    console.log("disconnect", data)
})