"""Port layer - Interfaces between domain and adapters

This layer defines the contracts (interfaces) that adapters must implement.
It separates the domain logic from external concerns.

Input Ports (Use Cases):
- InitTransaction: Initialize a new presentation transaction
- PostWalletResponse: Process wallet's credential submission
- GetWalletResponse: Retrieve wallet response for a transaction
- GetRequestObject: Retrieve JAR for wallet

Output Ports (External Dependencies):
- PresentationRepository: Presentation persistence
- JoseService: JWT/JWE operations
- ValidationService: Credential validation
- TrustService: Trust and certificate validation
- QrCodeService: QR code generation
"""

from eudi_verifier.port.input import *
from eudi_verifier.port.output import *
