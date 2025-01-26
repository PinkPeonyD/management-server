const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { createClient } = require("@supabase/supabase-js");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
if (!supabaseUrl || !supabaseKey) {
  throw new Error("Supabase URL and Key must be provided in .env file");
}
const supabase = createClient(supabaseUrl, supabaseKey);

app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
app.use(bodyParser.json());

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token is required" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

app.post("/api/users/register", async (req, res) => {
  console.log("POST /api/users/register request received", req.body);
  const { email, name, role, status, password } = req.body;

  if (!email || !name || !role || !status || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const { data: existingUser, error: checkEmailError } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (checkEmailError && checkEmailError.code !== "PGRST116") {
      throw checkEmailError;
    }

    if (existingUser) {
      return res
        .status(400)
        .json({ error: "User with this email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const last_seen = new Date().toISOString();
    const { data, error } = await supabase
      .from("users")
      .insert([
        { email, name, role, status, last_seen, password: hashedPassword },
      ])
      .select();

    if (error) {
      console.error("Supabase error:", error);
      throw error;
    }

    res.status(201).json({ user: data[0] });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/users/login", async (req, res) => {
  console.log("POST /api/users/login request received", req.body);
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.status === "blocked") {
      return res.status(403).json({ error: "User is blocked" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token, user });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/users/me", authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("id", req.user.userId)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ user });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/users/block", authenticateToken, async (req, res) => {
  console.log("POST /api/users/block request received", req.body);
  const { userIds } = req.body;

  if (!userIds || !Array.isArray(userIds)) {
    return res
      .status(400)
      .json({ error: "User IDs must be provided as an array" });
  }

  try {
    const { data, error } = await supabase
      .from("users")
      .update({ status: "blocked" })
      .in("id", userIds);

    if (error) {
      console.error("Supabase error:", error);
      throw error;
    }

    res.json({ userIds });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/users/unblock", authenticateToken, async (req, res) => {
  console.log("POST /api/users/unblock request received", req.body);
  const { userIds } = req.body;

  if (!userIds || !Array.isArray(userIds)) {
    return res
      .status(400)
      .json({ error: "User IDs must be provided as an array" });
  }

  try {
    const { data, error } = await supabase
      .from("users")
      .update({ status: "unblocked" })
      .in("id", userIds);

    if (error) {
      console.error("Supabase error:", error);
      throw error;
    }

    res.json({ userIds });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/users/delete", authenticateToken, async (req, res) => {
  console.log("POST /api/users/delete request received", req.body);
  const { userIds } = req.body;

  if (!userIds || !Array.isArray(userIds)) {
    return res
      .status(400)
      .json({ error: "User IDs must be provided as an array" });
  }

  try {
    const { data, error } = await supabase
      .from("users")
      .delete()
      .in("id", userIds);

    if (error) {
      console.error("Supabase error:", error);
      throw error;
    }

    res.json({ userIds });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from("users").select("*");

    if (error) {
      console.error("Supabase error:", error);
      throw error;
    }

    res.json({ users: data });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/users/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("id", id)
      .single();

    if (error) {
      console.error("Supabase error:", error);
      throw error;
    }

    res.json({ user: data });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/users/check-email", async (req, res) => {
  const { email } = req.body;

  try {
    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (error || !data) {
      return res.status(404).json({ error: "User not found" });
    }

    if (data.status === "blocked") {
      return res.status(403).json({ error: "User is blocked" });
    }

    res.json({ user: data });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post(
  "/api/users/check-current-user",
  authenticateToken,
  async (req, res) => {
    const { email } = req.body;

    try {
      const { data, error } = await supabase
        .from("users")
        .select("*")
        .eq("email", email)
        .single();

      if (error || !data) {
        return res.status(404).json({ error: "User not found" });
      }

      if (data.status === "blocked") {
        return res.status(403).json({ error: "User is blocked" });
      }

      res.json({ user: data });
    } catch (error) {
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
