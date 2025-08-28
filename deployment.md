# Project Guardian 2.0: PII Detection & Redaction Deployment Strategy

## 1. Proposed Architecture: The "Guardian Sidecar" Pattern

To address the PII leakage at the source, we propose deploying the PII detection and redaction service as a **Sidecar container** within the same Kubernetes Pod as the primary application services (e.g., the API integration service). This pattern is highly effective for microservices architectures like Flixkart's.

A sidecar is a secondary container that runs alongside the main application container. It shares the same network and storage, allowing it to augment the main application without being part of its codebase.



## 2. How It Works

1.  **Log Tailing:** The primary application container continues to write its raw, unstructured logs to a shared, ephemeral volume within the Pod (e.g., a Kubernetes `emptyDir`). This is a standard, low-latency logging practice.

2.  **Real-time Sanitization:** The "Guardian Sidecar" container runs our PII detection script as a persistent service. It continuously "tails" (monitors) the log file written by the main application.

3.  **PII Detection & Redaction:** As new log entries appear, the sidecar processes them in real-time, applying the PII detection rules to identify and redact sensitive data *on the spot*.

4.  **Secure Log Forwarding:** The sidecar then forwards the **sanitized, PII-free logs** to Flixkart's central logging infrastructure (e.g., ELK Stack, Splunk, or Datadog).

**Crucially, the raw, sensitive logs never leave the secure boundary of the Pod over the network.**

## 3. Justification and Advantages

This sidecar approach is chosen over alternatives (like an API Gateway plugin or a central processing service) for the following reasons:

* **✅ Low Latency:** Processing occurs locally within the Pod's memory and storage, eliminating network hops to a separate PII-scrubbing service. This ensures that adding security does not degrade the performance of the primary application.

* **✅ High Scalability:** The solution scales inherently with the application. When a service scales up to 100 pods, 100 Guardian Sidecars are automatically deployed alongside them. There is no central PII service that can become a bottleneck.

* **✅ Ease of Integration & Decoupling:** This is a "plug-and-play" solution. Application developers **do not need to modify their code** or even be aware of the PII detection logic. They simply continue to log as usual. The security layer is completely decoupled, allowing for independent updates and maintenance. This is a massive advantage for developer productivity and reduces the risk of inconsistent implementation across teams.

* **✅ Cost-Effectiveness:** The sidecar utilizes the existing compute resources allocated to the Pod. While it introduces a small CPU/memory overhead, it is far more cost-effective than provisioning, managing, and auto-scaling a separate, dedicated microservice cluster for PII redaction.

* **✅ Enhanced Security:** By sanitizing data at its source, we minimize the "blast radius." PII is never transmitted over the network in its raw form, closing the security gap identified in the initial audit. This approach also prevents PII from ever being stored, even temporarily, in centralized log collectors.

## 4. Alternatives Considered

* **API Gateway Plugin:** While useful for sanitizing incoming request/response bodies, it wouldn't catch PII generated internally by the application or in asynchronous log messages, which was the source of the fraud incident.
* **Centralized Log Sanitization Service:** This would require sending raw, sensitive logs over the network, creating a significant security risk of PII in transit. It also introduces a single point of failure.

The "Guardian Sidecar" pattern provides the most secure, scalable, and non-intrusive solution to fulfill the mission of Project Guardian 2.0.

#Installation

//git clone https://github.com/localh0ste/ProjectGuardian-Flixkart-Challenge


//python3 detector-python.py <file.csv>
