import GoogleStrategy from "passport-google-oauth20"

const googleStrategy = new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_ID,
    clientSecret: process.env.GOOGLE_SECRET,
    callbackURL: process.env.BE_URL + "/users/googleRedirect",
  },
  (_, __, profile, passportNext) => {
    // This callback function is executed when Google sends us a successfull response back
    // Here we gonna receive some informations about the user from Google (scopes --> email, profile)
    console.log("PROFILE: ", profile)
  }
)

export default googleStrategy
