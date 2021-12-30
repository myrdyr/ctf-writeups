const crypto = require("crypto");

function getSecretPasswordNumber(n) {
  return Math.PI.toFixed(48).toString().split(".")[1].slice(n, n+2);
}

function getPassword(date) {
  const passwords = {
    "06.12.19": "passord-" + getSecretPasswordNumber(3),
    "07.12.19": "passord-" + getSecretPasswordNumber(5),
    "08.12.19": "passord-" + getSecretPasswordNumber(8),
    "09.12.19": "passord-" + getSecretPasswordNumber(13),
    "10.12.19": "passord-" + getSecretPasswordNumber(21)
  };
  // 06.12.19: vi har ikke flere passord etter 10. Burde vurdere alternative
  // løsninger.
  return passwords[date] || `fant ikke passord for ${date}`;
}

function formatSalt(salt) {
  return salt.toLowerCase();
}

function encrypt(input) {
  // Bruk `decrypt` for å dekryptere

  const algorithm = "aes-192-cbc";
  // 06.12.19: husk å oppdatere denne hver dag!!!
  // 09.12.19: dette var sykt slitsomt. kan vi finne en bedre løsning?
  // 11.12.19: Krypteres permanent med dagens passord nå.
  // Denne funksjonen trengs vel ikke lenger?
  const password = getPassword("10.12.19");

  // 09.12.19: pepper er ikke et salt. Når vi på sikt krypterer utenfor serveren
  // burde vi oppdatere dette til noe mer vitenskapelig korrekt.
  // Natriumhydrogensulfat?
  // 11.12.19: Oppdatert med den kjemiske formelen ;)
  const key = crypto.scryptSync(password, formatSalt("pepper"), 24);

  const iv = Buffer.alloc(16, 0);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  
  let encrypted = cipher.update(input, "utf8", "hex");
  encrypted += cipher.final("hex");

  return encrypted;
}

function decrypt(password, salt, input) {
  const algorithm = "aes-192-cbc";
  
  const key = crypto.scryptSync(password, formatSalt(salt), 24);
  
  const iv = Buffer.alloc(16, 0);
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  
  let decrypted = decipher.update(input, 'hex','utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

function getFlag() {
  // Det er sikkert smartere å kryptere flagget først, og bare skrive inn det
  // krypterte resultatet her, enn å kryptere på serveren hver gang.
  // 11.12.19: Kryptert flagget nå. Vi kan sikkert slette encrypt-funksjonen?
  return "e5a8aadb885cd0db6c98140745daa3acf2d06edc17b08f1aff6daaca93017db9dc8d7ce7579214a92ca103129d0efcdd";
}

exports.handler = function main(event, context, callback) {
  let result = "";
  
  console.log(event.queryStringParameters.eval);
  
  // 😶
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SESSION_TOKEN;
  
  try {
    result = `${eval(event.queryStringParameters.eval)}`;
  } catch (e) {
    console.log(e);
    // 06.12.19: La til en god og informativ feilmelding.
   result = "Dette burde ikke skje...";
  }

  callback(null, {
    statusCode: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
    },
    body: result
  });
}
