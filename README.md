# Secured Inventory Management

## Table of Contents
1. Introduction  
2. Expanded Table of Contents  
   - Overview  
   - Features  
   - Requirements  
3. Technical Architecture  
   - High-Level Overview  
   - Technology Stack  
4. Database Schema Details  
   - Entity-Relationship Diagram  
   - Tables Overview  
5. Usage Instructions  
   - How to Run the Application  
   - API Endpoints  
6. Blockchain Implementation Details  
   - How Blockchain is Integrated  
   - Smart Contracts  
7. Initial Setup/Installation  
   - Dependencies  
   - Configuration  
8. Contributing  
   - How to Contribute  
   - Code of Conduct  
9. Screenshots

## Technical Architecture
The application is built on a microservices architecture, which allows for scalability and easy maintenance. Each component follows a specific domain responsibility, enhancing code organization and deployment.

## Database Schema Details
The following database entities are utilized to maintain secure inventory records:
- **Users**  
- **Items**  
- **Transactions**  

## Usage Instructions
To run the application, you need to have the following prerequisites installed:
- Node.js  
- npm/yarn  

For API usage, refer to the respective endpoints as documented.

## Blockchain Implementation Details
The application utilizes a blockchain for transparent transaction records. Smart contracts handle item transfer and ownership verification.

## Contributing
We welcome contributions! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting a pull request.

## Screenshots
![Homepage Screenshot](screenshots/homepage.png)
![Inventory Screenshot](screenshots/inventory.png)

## Initial Setup/Installation
Follow the steps to set up the project:
1. Clone the repository.  
2. Install dependencies using `npm install` or `yarn install`.  
3. Configure your database connection in the `.env` file.  
4. Run the application using `npm start`.

### Notes
Ensure you have installed all necessary dependencies to avoid issues during the application run.