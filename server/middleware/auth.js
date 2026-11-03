import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET;
const googleClientId = process.env.GOOGLE_CLIENT_ID;

// Google ID tokens are checked with Google before any of their claims are trusted
const verifyGoogleToken = async (token) => {
  const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(token)}`);
  if (!response.ok) throw new Error("Invalid Google token");

  const data = await response.json();
  if (!googleClientId || data.aud !== googleClientId) throw new Error("Google token audience mismatch");

  return data;
};

const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthenticated" });

    const isCustomAuth = token.length < 500;

    let decodedData;

    if (isCustomAuth) {
      decodedData = jwt.verify(token, secret);

      req.userId = decodedData?.id;
    } else {
      decodedData = await verifyGoogleToken(token);

      req.userId = decodedData?.sub;
    }

    next();
  } catch (error) {
    console.log(error.message);
    res.status(401).json({ message: "Unauthenticated" });
  }
};

export default auth;
