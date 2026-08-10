# Event definition recipes (Graylog UI)

Use these after streams exist. **Alerts → Event Definitions → Create event definition**.

## Template

1. **Condition type:** Filter & Aggregation  
2. **Search query:** from catalog  
3. **Streams:** attach matching `AJSIEM Low|Medium|High`  
4. **Group by:** optional `source`  
5. **Create events if:** count of messages `>` threshold in the catalog window  
6. **Priority:** Low=1, Medium=2, High=3  
7. **Notifications:** Email / HTTP (configure under Alerts → Notifications)

Import the machine-readable list from `alert-catalog.json` when scripting further automation.
