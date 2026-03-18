//testing out variables and types in TypeScript
let projectName: string = "Kevin's Project";
let version: number = 1;
let isActive: boolean = true;
let description: string = "This is a test project for Kevin.";

console.log(`Project Name: ${projectName}`);
console.log(`Version: ${version}`);
console.log(`Is Active: ${isActive}`);
console.log(`Description: ${description}`);

//arrays
let teamMembers: string[] = ["Geovanni", "Brian", "Abdul", "Kevin"]; //array of strings representing team members
let scores: number[] = [85, 90, 100, 92]; //array of numbers representing scores

teamMembers.push("Ivan"); //adding a new team member to the array
console.log("Team Members:", teamMembers); //displaying the updated list of team members

console.log("Number of team members:", teamMembers.length); //displaying the number of team members

for (const member of teamMembers) { //iterating through the team members and displaying each one
    console.log(" -", member);
}

//functions

// In Python:
//   def greet(name):
//       return f"Hello, {name}!"
//
// In TypeScript you specify input AND output types:

function greet(name: string): string { //function that takes a name as a parameter and returns a greeting message
    return 'Hello, ' + name + '! Welcome to ' + projectName + '.';
}

console.log(greet("Geovanni")); //calling the greet function with "Geovanni" as the argument and displaying the result

//function with multiple parameters
function add(a: number, b: number): number {
    return a + b;                               //function that takes two numbers as parameters and returns their sum
}

console.log("5 + 10 =", add(5, 10)); //calling the add function with 5 and 10 as arguments and displaying the result

// Arrow function (a shorter way to write functions)
const multiply = (a:number, b:number): number => a * b;

console.log("5 * 10 =", multiply(5, 10));   

// if/else

let score: number = 90;

if (score >= 90) {
    console.log("Grade: A");
} else if (score >= 80) {
    console.log("Grade: B");
} else if (score >= 70) {
    console.log("Grade: C");
}





