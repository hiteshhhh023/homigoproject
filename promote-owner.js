
require("dotenv").config();
const mongoose = require("mongoose");

const User = mongoose.model(
  "OwnerPromotionUser",
  new mongoose.Schema(
    { email: String, role: String },
    { collection: "users" }
  )
);

async function main() {
  const email = process.argv[2]?.trim().toLowerCase();

  if (!process.env.MONGODB_URI) {
    throw new Error(".env file mein MONGODB_URI nahi mila.");
  }

  if (!email) {
    console.log("Usage: node promote-owner.js your-email@example.com");
    return;
  }

  await mongoose.connect(process.env.MONGODB_URI);

  const result = await User.updateOne(
    { email },
    { $set: { role: "owner" } }
  );

  if (result.matchedCount === 0) {
    console.log("Account not found. Sign up on the website first.");
  } else {
    console.log("Owner access successfully enabled for:", email);
  }

  await mongoose.disconnect();
}

main().catch(async (error) => {
  console.error("Error:", error.message);
  await mongoose.disconnect().catch(() => {});
  process.exitCode = 1;
});
