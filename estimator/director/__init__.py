"""Estimating Director: the master agent that runs every job from request to signed job.

The Director decides what happens next and who does it. It never calculates
quantities or prices: those always come from the quick-estimate engine, the
takeoff engine and the pricing stack.
"""
