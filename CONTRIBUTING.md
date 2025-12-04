# Contributing to the Propulsion Engine Dashboard

Thank you for your interest in contributing.

## How to Contribute
1. Fork the repository and create a feature branch.
2. Make clear, documented changes that follow the structure of the project.
3. Ensure the app runs without errors before submitting.
4. Submit a pull request with a brief description of what you changed.

## Code Guidelines
- Keep code readable and consistent with existing formatting.
- Use meaningful commit messages.
- Avoid adding unnecessary dependencies.
- Do not modify core control logic without explaining the safety impact.

## Testing
Before opening a pull request:
- Start the server and verify there are no Flask or serial communication errors.
- Check that pages load and user authentication works.
- Ensure no breaking changes to the admin panel or dashboard UI.

## Security
Because this project controls real hardware:
- Never disable authentication or safety checks.
- Do not expose control routes without proper validation.
- Report any security issues privately to the project owner.

## Contact
For major changes or questions, open an issue before starting work.
