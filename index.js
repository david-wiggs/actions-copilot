const { createProbot } = require("probot");

// Only use this for local development
const app = require("./dist/index.js");

const probot = createProbot();
probot.load(app);
