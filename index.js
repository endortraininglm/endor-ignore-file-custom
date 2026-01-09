const _ = require('lodash');

console.log('Simple Node.js application demonstrating vulnerable dependency usage\n');

// Example 1: Using lodash merge (vulnerable to prototype pollution)
const userInput = {
  name: 'John Doe',
  email: 'john@example.com'
};

const defaultConfig = {
  theme: 'light',
  language: 'en'
};

// This merge operation exercises the vulnerable code path in lodash 4.17.19
const mergedConfig = _.merge({}, defaultConfig, userInput);
console.log('Merged configuration:', mergedConfig);

// Example 2: Using lodash template (string manipulation)
const templateString = 'Hello, <%= name %>! Your email is <%= email %>';
const compiled = _.template(templateString);
const result = compiled({ name: 'Alice', email: 'alice@example.com' });
console.log('\nTemplate result:', result);

// Example 3: Using lodash set with string path (vulnerable code path)
const obj = {};
_.set(obj, 'user.profile.name', 'Bob Smith');
_.set(obj, 'user.profile.email', 'bob@example.com');
console.log('\nObject with nested properties:', JSON.stringify(obj, null, 2));

// Example 4: String manipulation with lodash
const text = '  Hello World  ';
console.log('\nString manipulation:');
console.log('- Original:', `"${text}"`);
console.log('- Trimmed:', `"${_.trim(text)}"`);
console.log('- UpperCase:', `"${_.upperCase(text)}"`);
console.log('- CamelCase:', `"${_.camelCase(text)}"`);

// Example 5: Using mergeWith with customizer (exercises merge functionality)
const object = {
  'fruits': ['apple', 'banana']
};

const other = {
  'fruits': ['cherry', 'date']
};

const merged = _.mergeWith(object, other, (objValue, srcValue) => {
  if (_.isArray(objValue)) {
    return objValue.concat(srcValue);
  }
});

console.log('\nMerged arrays:', merged);

console.log('\n✅ Application completed successfully!');
console.log('⚠️  Note: This application uses lodash 4.17.19 which has known vulnerabilities:');
console.log('   - CVE-2020-8203 (Prototype Pollution)');
console.log('   - CVE-2019-10744 (Regular Expression Denial of Service)');
console.log('   - Command Injection vulnerability');
