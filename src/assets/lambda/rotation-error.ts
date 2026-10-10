/** Why a rotation cannot proceed, as reported in the `event.reason` field of a `validate_rotation` event. */
export type RotationStateReason = 'parameter_not_found' | 'unknown_event' | 'invalid_configuration';

/**
 * A request that is inconsistent with the parameter's state or the function's
 * configuration. The message is written by this package, so it is safe to log.
 */
export class RotationStateError extends Error {
  constructor(
    public readonly reason: RotationStateReason,
    message: string,
  ) {
    super(message);
    this.name = 'RotationStateError';
  }
}
