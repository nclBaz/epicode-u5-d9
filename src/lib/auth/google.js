import GoogleStrategy from "passport-google-oauth20"
import UsersModel from "../../api/users/model.js"
import { createAccessToken } from "./tools.js"

const googleStrategy = new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_ID,
    clientSecret: process.env.GOOGLE_SECRET,
    callbackURL: process.env.BE_URL + "/users/googleRedirect", // this needs to match exactly the endpoint that will be created which matches the one configured on Google Console
  },
  async (_, __, profile, passportNext) => {
    // This callback function is executed when Google sends us a successfull response back
    // Here we gonna receive some informations about the user from Google (scopes --> email, profile)
    console.log("PROFILE: ", profile)

    try {
      // 1. Check if the user is already in our db
      const user = await UsersModel.findOne({ email: profile._json.email })

      if (user) {
        // 2. If he/she is there --> generate an accessToken (optionally a refreshToken as well)
        const accessToken = await createAccessToken({
          _id: user._id,
          role: user.role,
        })
        console.log("ACCESS TOKEN: ", accessToken)

        // 2.1. Then we can go next (we go to the /googleRedirect route handler function) passing the token
        passportNext(null, { accessToken }) // passportNext takes as first parameter an error (if we had any), and as second parameter we can pass some informations to what is coming next
      } else {
        // 3. Else if the user is not in our db --> create that user
        const { given_name, family_name, email } = profile._json

        const newUser = new UsersModel({
          firstName: given_name,
          lastName: family_name,
          email,
          googleID: profile.id,
        })
        const createdUser = await newUser.save()
        // 3.1 Generate an accessToken (optionally a refreshToken)

        const accessToken = await createAccessToken({
          _id: createdUser._id,
          role: createdUser.role,
        })
        // 3.2 We go next passing the token
        passportNext(null, { accessToken })
      }
    } catch (error) {
      passportNext(error)
    }
  }
)

export default googleStrategy
