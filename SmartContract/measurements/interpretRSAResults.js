const fs = require('fs');

var measurements = JSON.parse(fs.readFileSync('./RSARegistration.json'));

let registrationSum = 0;
let registrationCount = 0;
let deploymentSum = 0;
let deplymentCount = 0;
let differentValues = {};

let add = function(value){
    if(differentValues["" + value]){
      differentValues["" + value]++;
    } else {
      differentValues["" + value] = 1;
    }
}

for(let i in measurements){

  if(measurements[i].function === "register"){
    registrationCount++;
    registrationSum += measurements[i].gas;
    add(measurements[i].gas);
  } else if(measurements[i].function === "deploy"){
    deplymentCount++;
    deploymentSum += measurements[i].gas;
    add(measurements[i].gas);
  } else {
    console.log("Error: function name does not match register or deployment")
  }
}

// console.log(registrationCount);
// console.log(registrationSum);
// console.log(deplymentCount);
// console.log(deploymentSum);
// console.log(differentValues);

console.log("Registration: " + (registrationSum / registrationCount));
console.log("Deployment: " + (deploymentSum / deplymentCount));
