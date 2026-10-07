# Accuracy Measurement

We will measure scanner accuracy using:

Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1 = 2 x Precision x Recall / (Precision + Recall)

TP is a real secret that was detected, FP is a false alarm, and FN is a real secret that was missed.

Recall is our priority metric, because a missed secret is more dangerous than a false alarm. This matches the near zero false negative goal in Task 1.

## Current baseline
Secrets.log has 10 planted findings and the integration test expects all 10, so recall on that file is 10 of 10. This is a small sample, so it does not show recall on real world logs.