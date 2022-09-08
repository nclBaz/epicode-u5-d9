import express from "express"
import listEndpoints from "express-list-endpoints"
import mongoose from "mongoose"
import cors from "cors"
import passport from "passport"
import cookieParser from "cookie-parser"
import usersRouter from "./api/users/index.js"
import {
  forbiddenErrorHandler,
  genericErroHandler,
  notFoundErrorHandler,
  unauthorizedErrorHandler,
} from "./errorHandlers.js"
import googleStrategy from "./lib/auth/google.js"

const server = express()
const port = process.env.PORT || 3001

passport.use("google", googleStrategy) // Do not forget to inform passport that we need to use googleStrategy

// ********************************* MIDDLEWARES *****************************
server.use(cors({ origin: process.env.FE_URL, credentials: true }))
server.use(cookieParser())
server.use(express.json())
server.use(passport.initialize()) // Do not forget to inform Express that we need to use passport

// ********************************** ENDPOINTS ******************************
server.use("/users", usersRouter)

// ******************************** ERROR HANDLERS ***************************
server.use(unauthorizedErrorHandler)
server.use(forbiddenErrorHandler)
server.use(notFoundErrorHandler)
server.use(genericErroHandler)

mongoose.connect(process.env.MONGO_CONNECTION_STRING)

mongoose.connection.on("connected", () => {
  console.log("Mongo Connected!")
  server.listen(port, () => {
    console.table(listEndpoints(server))
    console.log(`Server is listening on port ${port}`)
  })
})
