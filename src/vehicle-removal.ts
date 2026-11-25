import type { Pool } from 'pg';
import { HttpError } from './http.js';

/** Remove the garage entry and maintenance book without erasing workshop audit history. */
export async function removeCustomerVehicle(pool: Pool, customerId: string, vehicleId: string) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const owned = await client.query('SELECT id FROM vehicles WHERE id=$1 AND customer_id=$2 AND deleted_at IS NULL FOR UPDATE', [vehicleId, customerId]);
    if (!owned.rowCount) throw new HttpError(404, 'Moto introuvable pour ce client.');
    const active = await client.query(`SELECT 1 FROM tickets WHERE vehicle_id=$1 AND status NOT IN ('completed','cancelled')
      UNION ALL SELECT 1 FROM appointments WHERE vehicle_id=$1 AND status NOT IN ('Terminé','Annulé') LIMIT 1`, [vehicleId]);
    if (active.rowCount) throw new HttpError(409, 'Cette moto a une demande en cours. Terminez ou annulez cette demande avant de supprimer la moto.');
    await client.query('DELETE FROM maintenance WHERE vehicle_id=$1 AND customer_id=$2', [vehicleId, customerId]);
    await client.query('DELETE FROM vehicle_photos WHERE vehicle_id=$1', [vehicleId]);
    const history = await client.query('SELECT 1 FROM tickets WHERE vehicle_id=$1 UNION ALL SELECT 1 FROM appointments WHERE vehicle_id=$1 LIMIT 1', [vehicleId]);
    if (history.rowCount) {
      // Existing tickets and append-only events retain their vehicle reference.
      await client.query('UPDATE vehicles SET deleted_at=now() WHERE id=$1', [vehicleId]);
    } else {
      await client.query('DELETE FROM vehicles WHERE id=$1', [vehicleId]);
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
}
