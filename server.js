
require("dotenv").config();

const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is missing in your .env file.");
}

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

const { Schema } = mongoose;

const User = mongoose.model(
  "User",
  new Schema(
    {
      name: { type: String, required: true, trim: true },
      email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
      },
      password: { type: String, required: true, select: false },
      role: {
        type: String,
        enum: ["tenant", "owner"],
        default: "tenant"
      }
    },
    { timestamps: true, collection: "users" }
  )
);

const PG = mongoose.model(
  "PG",
  new Schema(
    {
      name: { type: String, required: true, trim: true },
      location: { type: String, required: true, trim: true },
      address: { type: String, required: true, trim: true },
      monthlyRent: { type: Number, required: true, min: 0 },
      roomType: { type: String, required: true },
      facilities: { type: Schema.Types.Mixed, default: [] },
      availableBeds: { type: Number, required: true, min: 0 },
      rating: { type: Number, default: 0, min: 0, max: 5 },
      image: { type: String, default: "" },
      images: {
        type: [{
          label: { type: String, trim: true, maxlength: 40 },
          url: { type: String, trim: true, maxlength: 2048 }
        }],
        default: []
      },
      ownerId: {
        type: Schema.Types.ObjectId,
        ref: "User",
        default: null
      }
    },
    { timestamps: true, collection: "pgs" }
  )
);

const Booking = mongoose.model(
  "Booking",
  new Schema(
    {
      pgId: {
        type: Schema.Types.ObjectId,
        ref: "PG",
        required: true
      },
      tenantId: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true
      },
      ownerId: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true
      },
      moveInDate: { type: Date, required: true },
      occupants: { type: Number, required: true, min: 1, max: 10 },
      message: { type: String, default: "", maxlength: 500 },
      status: {
        type: String,
        enum: ["Pending", "Processing", "Accepted", "Rejected"],
        default: "Pending"
      },
      payments: {
        type: [{
          receiptId: { type: String, required: true },
          method: {
            type: String,
            enum: ["upi", "qr", "bank"],
            required: true
          },
          status: {
            type: String,
            enum: ["Completed", "Declined"],
            required: true
          },
          amount: { type: Number, required: true, min: 0 },
          rating: { type: Number, min: 1, max: 5, default: null },
          createdAt: { type: Date, default: Date.now }
        }],
        default: []
      }
    },
    { timestamps: true, collection: "bookings" }
  )
);

const Notification = mongoose.model(
  "Notification",
  new Schema(
    {
      recipientId: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true,
        index: true
      },
      bookingId: {
        type: Schema.Types.ObjectId,
        ref: "Booking",
        required: true
      },
      type: {
        type: String,
        enum: ["booking_request", "booking_accepted", "booking_rejected"],
        required: true
      },
      actorName: { type: String, required: true, trim: true },
      message: { type: String, required: true, trim: true },
      readAt: { type: Date, default: null }
    },
    { timestamps: true, collection: "notifications" }
  )
);

async function createBookingNotification(recipientId, bookingId, type, actorId) {
  const actor = await User.findById(actorId).select("name").lean();
  if (!actor) throw new Error("Could not find the account for this notification.");

  const messages = {
    booking_request: "sent you a new booking request.",
    booking_accepted: "accepted your booking request.",
    booking_rejected: "declined your booking request."
  };

  return Notification.create({
    recipientId,
    bookingId,
    type,
    actorName: actor.name,
    message: messages[type]
  });
}

function createToken(user) {
  return jwt.sign(
    { userId: user._id.toString(), role: user.role },
    JWT_SECRET,
    { expiresIn: "1d" }
  );
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Please log in first." });
  }

  try {
    req.auth = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Your session has expired. Please log in again."
    });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.auth.role !== role) {
      return res.status(403).json({
        error: "You do not have permission to perform this action."
      });
    }
    next();
  };
}

function validId(id) {
  return mongoose.isValidObjectId(id);
}

function normalizeImages(value) {
  if (!Array.isArray(value) || value.length > 12) return null;

  const images = value
    .map(image => ({
      label: String(image?.label || "Other").trim(),
      url: String(image?.url || "").trim()
    }))
    .filter(image => image.url);

  for (const image of images) {
    if (!image.label || image.label.length > 40 || image.url.length > 2048) {
      return null;
    }

    try {
      const parsedUrl = new URL(image.url);
      if (!(["http:", "https:"].includes(parsedUrl.protocol))) return null;
    } catch {
      return null;
    }
  }

  return images;
}

app.get("/api/status", (req, res) => {
  res.json({ success: true, message: "HOMIGO server is running." });
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || password.length < 6) {
      return res.status(400).json({
        error: "Name, valid email and password of at least 6 characters are required."
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({ error: "Email is already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: "tenant"
    });

    res.status(201).json({
      token: createToken(user),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({
      error: "Could not create account.",
      details: error.code === 11000 ? "Email is already registered." : error.message
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const user = await User.findOne({ email }).select("+password");

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    res.json({
      token: createToken(user),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Could not log in.", details: error.message });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.auth.userId).select("-password");

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Could not load account." });
  }
});

app.get("/api/pgs", async (req, res) => {
  try {
    const pgs = await PG.find().sort({ createdAt: -1 }).lean();
    res.json(pgs);
  } catch (error) {
    res.status(500).json({ error: "Could not load PG listings." });
  }
});

app.get("/api/pgs/:id", async (req, res) => {
  try {
    if (!validId(req.params.id)) {
      return res.status(400).json({ error: "Invalid PG ID." });
    }

    const pg = await PG.findById(req.params.id).lean();

    if (!pg) {
      return res.status(404).json({ error: "PG not found." });
    }

    res.json(pg);
  } catch (error) {
    res.status(500).json({ error: "Could not load PG details." });
  }
});

app.post("/api/pgs", requireAuth, requireRole("owner"), async (req, res) => {
  try {
    const {
      name,
      location,
      address,
      monthlyRent,
      roomType,
      facilities,
      availableBeds,
      rating,
      image,
      images
    } = req.body;

    if (
      !String(name || "").trim() ||
      !String(location || "").trim() ||
      !String(address || "").trim() ||
      !String(roomType || "").trim() ||
      !Number.isFinite(Number(monthlyRent)) ||
      Number(monthlyRent) < 0 ||
      !Number.isInteger(Number(availableBeds)) ||
      Number(availableBeds) < 0
    ) {
      return res.status(400).json({ error: "Please enter valid PG details." });
    }

    const normalizedImages = normalizeImages(
      images === undefined
        ? (image ? [{ label: "Cover", url: image }] : [])
        : images
    );

    if (!normalizedImages) {
      return res.status(400).json({
        error: "Add up to 12 valid photo URLs using HTTP or HTTPS."
      });
    }

    const pg = await PG.create({
      name,
      location,
      address,
      monthlyRent: Number(monthlyRent),
      roomType,
      facilities: facilities || [],
      availableBeds: Number(availableBeds),
      rating: rating === "" || rating == null ? 0 : Number(rating),
      image: normalizedImages[0]?.url || "",
      images: normalizedImages,
      ownerId: req.auth.userId
    });

    res.status(201).json({ message: "PG added successfully.", pg });
  } catch (error) {
    res.status(500).json({
      error: "Could not add PG.",
      details: error.message
    });
  }
});

app.get("/api/owner/pgs", requireAuth, requireRole("owner"), async (req, res) => {
  try {
    const pgs = await PG.find({ ownerId: req.auth.userId })
      .sort({ createdAt: -1 })
      .lean();

    res.json(pgs);
  } catch (error) {
    res.status(500).json({ error: "Could not load your PG listings." });
  }
});

app.put(
  "/api/owner/pgs/:id",
  requireAuth,
  requireRole("owner"),
  async (req, res) => {
    try {
      if (!validId(req.params.id)) {
        return res.status(400).json({ error: "Invalid PG ID." });
      }

      const allowedFields = [
        "name",
        "location",
        "address",
        "monthlyRent",
        "roomType",
        "facilities",
        "availableBeds",
        "rating",
        "image",
        "images"
      ];

      const updates = {};

      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      if (updates.images !== undefined) {
        updates.images = normalizeImages(updates.images);
        if (!updates.images) {
          return res.status(400).json({
            error: "Add up to 12 valid photo URLs using HTTP or HTTPS."
          });
        }
        updates.image = updates.images[0]?.url || "";
      } else if (updates.image !== undefined) {
        const normalizedImages = normalizeImages(
          updates.image ? [{ label: "Cover", url: updates.image }] : []
        );
        if (!normalizedImages) {
          return res.status(400).json({ error: "Please enter a valid photo URL." });
        }
        updates.images = normalizedImages;
      }

      if (updates.monthlyRent !== undefined) {
        updates.monthlyRent = Number(updates.monthlyRent);
        if (!Number.isFinite(updates.monthlyRent) || updates.monthlyRent < 0) {
          return res.status(400).json({ error: "Invalid monthly rent." });
        }
      }

      if (updates.availableBeds !== undefined) {
        updates.availableBeds = Number(updates.availableBeds);
        if (!Number.isInteger(updates.availableBeds) || updates.availableBeds < 0) {
          return res.status(400).json({ error: "Invalid available beds." });
        }
      }

      if (updates.rating !== undefined) {
        updates.rating = Number(updates.rating);
        if (!Number.isFinite(updates.rating) || updates.rating < 0 || updates.rating > 5) {
          return res.status(400).json({ error: "Rating must be between 0 and 5." });
        }
      }

      const pg = await PG.findOneAndUpdate(
        { _id: req.params.id, ownerId: req.auth.userId },
        { $set: updates },
        { new: true, runValidators: true }
      );

      if (!pg) {
        return res.status(404).json({ error: "PG not found or not owned by you." });
      }

      res.json({ message: "PG updated successfully.", pg });
    } catch (error) {
      res.status(500).json({
        error: "Could not update PG.",
        details: error.message
      });
    }
  }
);

app.delete(
  "/api/owner/pgs/:id",
  requireAuth,
  requireRole("owner"),
  async (req, res) => {
    try {
      if (!validId(req.params.id)) {
        return res.status(400).json({ error: "Invalid PG ID." });
      }

      const pg = await PG.findOneAndDelete({
        _id: req.params.id,
        ownerId: req.auth.userId
      });

      if (!pg) {
        return res.status(404).json({ error: "PG not found or not owned by you." });
      }

      await Booking.deleteMany({ pgId: pg._id });

      res.json({ message: "PG and its booking requests deleted successfully." });
    } catch (error) {
      res.status(500).json({
        error: "Could not delete PG.",
        details: error.message
      });
    }
  }
);

app.post(
  "/api/bookings",
  requireAuth,
  requireRole("tenant"),
  async (req, res) => {
    try {
      const { pgId, moveInDate, occupants, message } = req.body;

      if (!validId(pgId)) {
        return res.status(400).json({ error: "Invalid PG ID." });
      }

      if (
        typeof moveInDate !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(moveInDate)
      ) {
        return res.status(400).json({ error: "Please select a valid move-in date." });
      }

      const date = new Date(`${moveInDate}T00:00:00.000Z`);
      if (
        Number.isNaN(date.getTime()) ||
        date.toISOString().slice(0, 10) !== moveInDate ||
        moveInDate < new Date().toISOString().slice(0, 10)
      ) {
        return res.status(400).json({ error: "Move-in date cannot be in the past." });
      }

      const count = Number(occupants);
      if (!Number.isInteger(count) || count < 1 || count > 10) {
        return res.status(400).json({ error: "Occupants must be between 1 and 10." });
      }

      if (typeof message === "string" && message.length > 500) {
        return res.status(400).json({ error: "Message cannot exceed 500 characters." });
      }

      const pg = await PG.findById(pgId);

      if (!pg) {
        return res.status(404).json({ error: "PG not found." });
      }

      if (!pg.ownerId) {
        return res.status(400).json({
          error: "This older PG listing has no assigned owner and cannot accept booking requests."
        });
      }

      if (pg.availableBeds < count) {
        return res.status(409).json({
          error: `Only ${pg.availableBeds} beds are currently available.`
        });
      }

      const existing = await Booking.findOne({
        pgId: pg._id,
        tenantId: req.auth.userId,
        status: { $in: ["Pending", "Processing", "Accepted"] }
      });

      if (existing) {
        return res.status(409).json({
          error: "You already have an active request for this PG."
        });
      }

      const booking = await Booking.create({
        pgId: pg._id,
        tenantId: req.auth.userId,
        ownerId: pg.ownerId,
        moveInDate: date,
        occupants: count,
        message: typeof message === "string" ? message.trim() : ""
      });

      try {
        await createBookingNotification(
          pg.ownerId,
          booking._id,
          "booking_request",
          req.auth.userId
        );
      } catch (error) {
        await Booking.deleteOne({ _id: booking._id });
        throw error;
      }

      res.status(201).json({
        message: "Booking request sent successfully.",
        booking
      });
    } catch (error) {
      res.status(500).json({
        error: "Could not send booking request.",
        details: error.message
      });
    }
  }
);

app.get("/api/notifications", requireAuth, async (req, res) => {
  try {
    const [notifications, unreadCount] = await Promise.all([
      Notification.find({ recipientId: req.auth.userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Notification.countDocuments({
        recipientId: req.auth.userId,
        readAt: null
      })
    ]);

    res.json({ notifications, unreadCount });
  } catch (error) {
    res.status(500).json({
      error: "Could not load notifications.",
      details: error.message
    });
  }
});

app.patch("/api/notifications/read", requireAuth, async (req, res) => {
  try {
    const result = await Notification.updateMany(
      { recipientId: req.auth.userId, readAt: null },
      { $set: { readAt: new Date() } }
    );
    res.json({ message: "Notifications marked as read.", updated: result.modifiedCount });
  } catch (error) {
    res.status(500).json({
      error: "Could not update notifications.",
      details: error.message
    });
  }
});

app.post(
  "/api/bookings/:id/demo-payments",
  requireAuth,
  requireRole("tenant"),
  async (req, res) => {
    try {
      if (!validId(req.params.id)) {
        return res.status(400).json({ error: "Invalid booking ID." });
      }

      const method = String(req.body.method || "");
      const outcome = String(req.body.outcome || "");
      if (!["upi", "qr", "bank"].includes(method)) {
        return res.status(400).json({ error: "Choose a valid demo payment option." });
      }
      if (!["Completed", "Declined"].includes(outcome)) {
        return res.status(400).json({ error: "Choose a valid demo payment outcome." });
      }

      const booking = await Booking.findOne({
        _id: req.params.id,
        tenantId: req.auth.userId
      })
        .populate("pgId", "name monthlyRent")
        .populate("tenantId", "name")
        .populate("ownerId", "name");

      if (!booking) {
        return res.status(404).json({ error: "Booking not found." });
      }
      if (booking.status !== "Accepted") {
        return res.status(409).json({
          error: "Demo payment is available only after the owner accepts the booking."
        });
      }

      const payment = {
        receiptId: `HOMIGO-DEMO-${new mongoose.Types.ObjectId().toString().toUpperCase()}`,
        method,
        status: outcome,
        amount: Number(booking.pgId.monthlyRent),
        createdAt: new Date()
      };
      booking.payments.push(payment);
      await booking.save();

      res.status(201).json({
        payment,
        bookingId: booking._id,
        pgName: booking.pgId.name,
        tenantName: booking.tenantId.name,
        ownerName: booking.ownerId.name
      });
    } catch (error) {
      res.status(500).json({
        error: "Could not save the demo payment receipt.",
        details: error.message
      });
    }
  }
);

app.patch(
  "/api/bookings/:id/demo-payments/:receiptId/rating",
  requireAuth,
  requireRole("tenant"),
  async (req, res) => {
    try {
      if (!validId(req.params.id)) {
        return res.status(400).json({ error: "Invalid booking ID." });
      }
      const rating = Number(req.body.rating);
      if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
        return res.status(400).json({ error: "Rating must be between 1 and 5." });
      }

      const booking = await Booking.findOne({
        _id: req.params.id,
        tenantId: req.auth.userId
      });
      if (!booking) {
        return res.status(404).json({ error: "Booking not found." });
      }

      const payment = booking.payments.find(
        item => item.receiptId === req.params.receiptId
      );
      if (!payment) {
        return res.status(404).json({ error: "Demo receipt not found." });
      }

      payment.rating = rating;
      await booking.save();
      res.json({ message: "Thanks for rating your demo checkout.", rating });
    } catch (error) {
      res.status(500).json({
        error: "Could not save your rating.",
        details: error.message
      });
    }
  }
);

app.get("/api/bookings/mine", requireAuth, requireRole("tenant"), async (req, res) => {
  try {
    const bookings = await Booking.find({ tenantId: req.auth.userId })
      .populate("pgId", "name location address monthlyRent image")
      .populate("ownerId", "name email")
      .populate("tenantId", "name email")
      .sort({ createdAt: -1 })
      .lean();

    res.json(bookings);
  } catch (error) {
    res.status(500).json({ error: "Could not load your booking requests." });
  }
});

app.get(
  "/api/owner/bookings",
  requireAuth,
  requireRole("owner"),
  async (req, res) => {
    try {
      const bookings = await Booking.find({ ownerId: req.auth.userId })
        .populate("pgId", "name location address monthlyRent image")
        .populate("tenantId", "name email")
        .sort({ createdAt: -1 })
        .lean();

      res.json(bookings);
    } catch (error) {
      res.status(500).json({ error: "Could not load booking requests." });
    }
  }
);

app.patch(
  "/api/owner/bookings/:id",
  requireAuth,
  requireRole("owner"),
  async (req, res) => {
    let claimedBooking = null;
    let bedsReserved = false;
    let notificationId = null;

    try {
      if (!validId(req.params.id)) {
        return res.status(400).json({ error: "Invalid booking ID." });
      }

      const action = String(req.body.status || "");
      if (!["Accepted", "Rejected"].includes(action)) {
        return res.status(400).json({
          error: "Status must be Accepted or Rejected."
        });
      }

      claimedBooking = await Booking.findOneAndUpdate(
        {
          _id: req.params.id,
          ownerId: req.auth.userId,
          status: "Pending"
        },
        { $set: { status: "Processing" } },
        { new: true }
      );

      if (!claimedBooking) {
        const booking = await Booking.findOne({
          _id: req.params.id,
          ownerId: req.auth.userId
        });

        if (!booking) {
          return res.status(404).json({ error: "Booking request not found." });
        }

        return res.status(409).json({
          error: `This request is already ${booking.status.toLowerCase()} or being processed.`
        });
      }

      if (action === "Rejected") {
        const notification = await createBookingNotification(
          claimedBooking.tenantId,
          claimedBooking._id,
          "booking_rejected",
          req.auth.userId
        );
        notificationId = notification._id;
        claimedBooking.status = "Rejected";
        await claimedBooking.save();

        return res.json({
          message: "Booking request rejected.",
          booking: claimedBooking
        });
      }

      const pg = await PG.findOneAndUpdate(
        {
          _id: claimedBooking.pgId,
          ownerId: req.auth.userId,
          availableBeds: { $gte: claimedBooking.occupants }
        },
        { $inc: { availableBeds: -claimedBooking.occupants } },
        { new: true }
      );

      if (!pg) {
        await Booking.updateOne(
          { _id: claimedBooking._id, status: "Processing" },
          { $set: { status: "Pending" } }
        );

        return res.status(409).json({
          error: "Not enough available beds. Update the PG availability before accepting."
        });
      }

      bedsReserved = true;

      const notification = await createBookingNotification(
        claimedBooking.tenantId,
        claimedBooking._id,
        "booking_accepted",
        req.auth.userId
      );
      notificationId = notification._id;
      claimedBooking.status = "Accepted";
      await claimedBooking.save();

      res.json({
        message: "Booking request accepted.",
        booking: claimedBooking,
        availableBeds: pg.availableBeds
      });
    } catch (error) {
      if (notificationId) {
        await Notification.deleteOne({ _id: notificationId }).catch(cleanupError => {
          console.error("Could not remove a rolled-back booking notification:", cleanupError.message);
        });
      }
      if (claimedBooking) {
        if (bedsReserved) {
          await PG.updateOne(
            { _id: claimedBooking.pgId, ownerId: req.auth.userId },
            { $inc: { availableBeds: claimedBooking.occupants } }
          ).catch(() => {});
        }

        await Booking.updateOne(
          { _id: claimedBooking._id, status: "Processing" },
          { $set: { status: "Pending" } }
        ).catch(() => {});
      }

      res.status(500).json({
        error: "Could not update booking request.",
        details: error.message
      });
    }
  }
);

app.use("/api", (req, res) => {
  res.status(404).json({ error: "API route not found." });
});

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB connected successfully!");

    app.listen(PORT, () => {
      console.log(`HOMIGO is running at http://localhost:${PORT}`);
      console.log(`All PGs: http://localhost:${PORT}/api/pgs`);
    });
  })
  .catch((error) => {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1);
  });
